//go:build ignore

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#define MAX_FILENAME_LEN 256
#define MAX_ARGS_LEN 512

// Process event structure
struct process_event {
    __u32 pid;
    __u32 ppid;
    __u32 uid;
    __u32 gid;
    __u64 timestamp;
    __u32 action;      // 0=fork, 1=exec, 2=exit
    __u32 exit_code;
    char comm[16];
    char filename[MAX_FILENAME_LEN];
    char args[MAX_ARGS_LEN];
};

// File event structure
struct file_event {
    __u32 pid;
    __u64 timestamp;
    __u32 action;      // 0=open, 1=read, 2=write, 3=close
    __u32 flags;
    __u32 mode;
    __u64 bytes;
    char comm[16];
    char filename[MAX_FILENAME_LEN];
};

// Ring buffers
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} process_events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} file_events SEC(".maps");

// Process tracking
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u32);
    __type(value, struct process_event);
} process_info SEC(".maps");

// Tracepoint for process fork
SEC("tp/sched/sched_process_fork")
int trace_sched_process_fork(struct trace_event_raw_sched_process_fork *ctx)
{
    struct process_event *event;
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;

    event = bpf_ringbuf_reserve(&process_events, sizeof(*event), 0);
    if (!event)
        return 0;

    event->pid = BPF_CORE_READ(ctx, child_pid);
    event->ppid = pid;
    event->uid = bpf_get_current_uid_gid() & 0xffffffff;
    event->gid = bpf_get_current_uid_gid() >> 32;
    event->timestamp = bpf_ktime_get_ns();
    event->action = 0; // fork
    event->exit_code = 0;

    bpf_get_current_comm(&event->comm, sizeof(event->comm));

    bpf_ringbuf_submit(event, 0);
    return 0;
}

// Tracepoint for process exec
SEC("tp/sched/sched_process_exec")
int trace_sched_process_exec(struct trace_event_raw_sched_process_exec *ctx)
{
    struct process_event *event;
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;

    event = bpf_ringbuf_reserve(&process_events, sizeof(*event), 0);
    if (!event)
        return 0;

    event->pid = pid;
    event->ppid = BPF_CORE_READ(ctx, old_pid); // This may need adjustment
    event->uid = bpf_get_current_uid_gid() & 0xffffffff;
    event->gid = bpf_get_current_uid_gid() >> 32;
    event->timestamp = bpf_ktime_get_ns();
    event->action = 1; // exec
    event->exit_code = 0;

    bpf_get_current_comm(&event->comm, sizeof(event->comm));

    // Try to get filename from task struct
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    if (task) {
        struct mm_struct *mm = BPF_CORE_READ(task, mm);
        if (mm) {
            struct file *exe_file = BPF_CORE_READ(mm, exe_file);
            if (exe_file) {
                struct path path = BPF_CORE_READ(exe_file, f_path);
                struct dentry *dentry = BPF_CORE_READ(path, dentry);
                if (dentry) {
                    bpf_probe_read_kernel_str(&event->filename, MAX_FILENAME_LEN,
                                            BPF_CORE_READ(dentry, d_name.name));
                }
            }
        }
    }

    bpf_ringbuf_submit(event, 0);
    return 0;
}

// Tracepoint for process exit
SEC("tp/sched/sched_process_exit")
int trace_sched_process_exit(struct trace_event_raw_sched_process_exit *ctx)
{
    struct process_event *event;
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;

    event = bpf_ringbuf_reserve(&process_events, sizeof(*event), 0);
    if (!event)
        return 0;

    event->pid = pid;
    event->ppid = 0; // Will be filled from process_info if available
    event->uid = bpf_get_current_uid_gid() & 0xffffffff;
    event->gid = bpf_get_current_uid_gid() >> 32;
    event->timestamp = bpf_ktime_get_ns();
    event->action = 2; // exit

    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    if (task) {
        event->exit_code = BPF_CORE_READ(task, exit_code);
        event->ppid = BPF_CORE_READ(task, real_parent, pid);
    }

    bpf_get_current_comm(&event->comm, sizeof(event->comm));

    bpf_ringbuf_submit(event, 0);

    // Clean up process_info map
    bpf_map_delete_elem(&process_info, &pid);
    return 0;
}

// Tracepoint for file open
SEC("tp/syscalls/sys_enter_openat")
int trace_sys_enter_openat(struct trace_event_raw_sys_enter *ctx)
{
    struct file_event *event;
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;

    event = bpf_ringbuf_reserve(&file_events, sizeof(*event), 0);
    if (!event)
        return 0;

    event->pid = pid;
    event->timestamp = bpf_ktime_get_ns();
    event->action = 0; // open
    event->flags = (unsigned long)ctx->args[2];
    event->mode = (unsigned long)ctx->args[3];
    event->bytes = 0;

    bpf_get_current_comm(&event->comm, sizeof(event->comm));

    // Get filename
    char *filename = (char *)ctx->args[1];
    if (filename) {
        bpf_probe_read_user_str(&event->filename, MAX_FILENAME_LEN, filename);
    }

    bpf_ringbuf_submit(event, 0);
    return 0;
}

// Kprobe for VFS read
SEC("kprobe/vfs_read")
int BPF_KPROBE(kprobe_vfs_read, struct file *file, char __user *buf,
               size_t count, loff_t *pos)
{
    struct file_event *event;
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;

    event = bpf_ringbuf_reserve(&file_events, sizeof(*event), 0);
    if (!event)
        return 0;

    event->pid = pid;
    event->timestamp = bpf_ktime_get_ns();
    event->action = 1; // read
    event->flags = 0;
    event->mode = 0;
    event->bytes = count;

    bpf_get_current_comm(&event->comm, sizeof(event->comm));

    // Get filename from file structure
    if (file) {
        struct path path = BPF_CORE_READ(file, f_path);
        struct dentry *dentry = BPF_CORE_READ(path, dentry);
        if (dentry) {
            bpf_probe_read_kernel_str(&event->filename, MAX_FILENAME_LEN,
                                    BPF_CORE_READ(dentry, d_name.name));
        }
    }

    bpf_ringbuf_submit(event, 0);
    return 0;
}

// Kprobe for VFS write
SEC("kprobe/vfs_write")
int BPF_KPROBE(kprobe_vfs_write, struct file *file, const char __user *buf,
               size_t count, loff_t *pos)
{
    struct file_event *event;
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;

    event = bpf_ringbuf_reserve(&file_events, sizeof(*event), 0);
    if (!event)
        return 0;

    event->pid = pid;
    event->timestamp = bpf_ktime_get_ns();
    event->action = 2; // write
    event->flags = 0;
    event->mode = 0;
    event->bytes = count;

    bpf_get_current_comm(&event->comm, sizeof(event->comm));

    // Get filename from file structure
    if (file) {
        struct path path = BPF_CORE_READ(file, f_path);
        struct dentry *dentry = BPF_CORE_READ(path, dentry);
        if (dentry) {
            bpf_probe_read_kernel_str(&event->filename, MAX_FILENAME_LEN,
                                    BPF_CORE_READ(dentry, d_name.name));
        }
    }

    bpf_ringbuf_submit(event, 0);
    return 0;
}

char _license[] SEC("license") = "GPL";