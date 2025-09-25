//go:build ignore

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#define MAX_FILENAME_LEN 256
#define MAX_DATA_SIZE 1024

// AI model event structure
struct ai_model_event {
    __u32 pid;
    __u64 timestamp;
    __u32 action;       // 0=load, 1=inference, 2=modify, 3=access, 4=suspicious
    __u32 threat_level; // 0=low, 1=medium, 2=high, 3=critical
    __u64 data_size;
    char comm[16];
    char model_path[MAX_FILENAME_LEN];
    char description[MAX_DATA_SIZE];
};

// Ring buffer for AI model events
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} ai_events SEC(".maps");

// Model file tracking
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, char[MAX_FILENAME_LEN]);
    __type(value, __u64); // last access time
} model_files SEC(".maps");

// AI process tracking
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 512);
    __type(key, __u32); // PID
    __type(value, __u32); // flags for AI-related activities
} ai_processes SEC(".maps");

// Suspicious activity counters
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 256);
    __type(key, __u32); // PID
    __type(value, __u32); // counter
} suspicious_activity SEC(".maps");

// Helper function to check if file is AI model
static __always_inline int is_ai_model_file(const char *filename)
{
    // Check for common AI model file extensions
    int len = bpf_strnlen(filename, MAX_FILENAME_LEN);
    if (len < 4)
        return 0;

    // Check for .pt (PyTorch), .pth (PyTorch), .pb (TensorFlow), .onnx, .h5 (Keras)
    if (len > 3) {
        if ((filename[len-3] == '.' && filename[len-2] == 'p' && filename[len-1] == 't') ||
            (len > 4 && filename[len-4] == '.' && filename[len-3] == 'p' && filename[len-2] == 't' && filename[len-1] == 'h') ||
            (len > 3 && filename[len-3] == '.' && filename[len-2] == 'p' && filename[len-1] == 'b') ||
            (len > 5 && filename[len-5] == '.' && filename[len-4] == 'o' && filename[len-3] == 'n' && filename[len-2] == 'n' && filename[len-1] == 'x') ||
            (len > 3 && filename[len-3] == '.' && filename[len-2] == 'h' && filename[len-1] == '5')) {
            return 1;
        }
    }

    // Check for model directory patterns
    if (bpf_strstr(filename, "/models/") || bpf_strstr(filename, "/checkpoints/") ||
        bpf_strstr(filename, "/weights/") || bpf_strstr(filename, "/trained_models/")) {
        return 1;
    }

    return 0;
}

// Helper function to check if process is AI-related
static __always_inline int is_ai_process(const char *comm)
{
    return (bpf_strncmp(comm, "python", 6) == 0 ||
            bpf_strncmp(comm, "pytorch", 7) == 0 ||
            bpf_strncmp(comm, "tensorflow", 10) == 0 ||
            bpf_strncmp(comm, "jupyter", 7) == 0 ||
            bpf_strncmp(comm, "ipython", 7) == 0);
}

// Monitor file access for AI models
SEC("kprobe/vfs_open")
int BPF_KPROBE(kprobe_ai_file_access, struct path *path, struct file *file)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;

    char filename[MAX_FILENAME_LEN];
    char comm[16];

    bpf_get_current_comm(&comm, sizeof(comm));

    // Get filename from path
    if (path) {
        struct dentry *dentry = BPF_CORE_READ(path, dentry);
        if (dentry) {
            bpf_probe_read_kernel_str(&filename, MAX_FILENAME_LEN,
                                    BPF_CORE_READ(dentry, d_name.name));
        }
    }

    // Check if this is an AI model file
    if (!is_ai_model_file(filename))
        return 0;

    struct ai_model_event *event;
    event = bpf_ringbuf_reserve(&ai_events, sizeof(*event), 0);
    if (!event)
        return 0;

    event->pid = pid;
    event->timestamp = bpf_ktime_get_ns();
    event->action = 3; // access
    event->data_size = 0;

    bpf_probe_read_kernel_str(&event->comm, sizeof(event->comm), comm);
    bpf_probe_read_kernel_str(&event->model_path, sizeof(event->model_path), filename);

    // Determine threat level based on process and access pattern
    if (is_ai_process(comm)) {
        event->threat_level = 0; // low - normal AI process accessing model
    } else {
        event->threat_level = 2; // high - non-AI process accessing model files
        bpf_snprintf(event->description, sizeof(event->description),
                    "Non-AI process accessing model file");
    }

    // Track model file access
    __u64 current_time = bpf_ktime_get_ns();
    bpf_map_update_elem(&model_files, &filename, &current_time, BPF_ANY);

    // Mark process as AI-related if accessing AI models
    __u32 ai_flag = 1;
    bpf_map_update_elem(&ai_processes, &pid, &ai_flag, BPF_ANY);

    bpf_ringbuf_submit(event, 0);
    return 0;
}

// Monitor large file writes that might indicate model exfiltration
SEC("kprobe/vfs_write")
int BPF_KPROBE(kprobe_ai_model_exfiltration, struct file *file, const char __user *buf,
               size_t count, loff_t *pos)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;

    // Only monitor large writes that could be model exfiltration
    if (count < 10 * 1024 * 1024) // 10MB threshold
        return 0;

    char comm[16];
    bpf_get_current_comm(&comm, sizeof(comm));

    // Check if this is from an AI process
    __u32 *ai_flag = bpf_map_lookup_elem(&ai_processes, &pid);
    if (!ai_flag)
        return 0;

    char filename[MAX_FILENAME_LEN];
    if (file) {
        struct path path = BPF_CORE_READ(file, f_path);
        struct dentry *dentry = BPF_CORE_READ(path, dentry);
        if (dentry) {
            bpf_probe_read_kernel_str(&filename, MAX_FILENAME_LEN,
                                    BPF_CORE_READ(dentry, d_name.name));
        }
    }

    struct ai_model_event *event;
    event = bpf_ringbuf_reserve(&ai_events, sizeof(*event), 0);
    if (!event)
        return 0;

    event->pid = pid;
    event->timestamp = bpf_ktime_get_ns();
    event->action = 4; // suspicious activity
    event->threat_level = 3; // critical
    event->data_size = count;

    bpf_probe_read_kernel_str(&event->comm, sizeof(event->comm), comm);
    bpf_probe_read_kernel_str(&event->model_path, sizeof(event->model_path), filename);
    bpf_snprintf(event->description, sizeof(event->description),
                "Large file write detected - potential model exfiltration (%lu bytes)", count);

    // Increment suspicious activity counter
    __u32 *counter = bpf_map_lookup_elem(&suspicious_activity, &pid);
    if (counter) {
        (*counter)++;
    } else {
        __u32 initial_count = 1;
        bpf_map_update_elem(&suspicious_activity, &pid, &initial_count, BPF_ANY);
    }

    bpf_ringbuf_submit(event, 0);
    return 0;
}

// Monitor Python/PyTorch library loading
SEC("uprobe/dlopen")
int BPF_KPROBE(uprobe_ai_library_load, const char *filename, int flag)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;

    char filepath[MAX_FILENAME_LEN];
    if (filename) {
        bpf_probe_read_user_str(&filepath, MAX_FILENAME_LEN, filename);
    } else {
        return 0;
    }

    // Check for AI-related libraries
    if (!bpf_strstr(filepath, "torch") && !bpf_strstr(filepath, "tensorflow") &&
        !bpf_strstr(filepath, "numpy") && !bpf_strstr(filepath, "sklearn") &&
        !bpf_strstr(filepath, "keras"))
        return 0;

    char comm[16];
    bpf_get_current_comm(&comm, sizeof(comm));

    struct ai_model_event *event;
    event = bpf_ringbuf_reserve(&ai_events, sizeof(*event), 0);
    if (!event)
        return 0;

    event->pid = pid;
    event->timestamp = bpf_ktime_get_ns();
    event->action = 0; // load
    event->threat_level = 0; // low
    event->data_size = 0;

    bpf_probe_read_kernel_str(&event->comm, sizeof(event->comm), comm);
    bpf_probe_read_user_str(&event->model_path, sizeof(event->model_path), filepath);
    bpf_snprintf(event->description, sizeof(event->description),
                "AI library loaded");

    // Mark process as AI-related
    __u32 ai_flag = 1;
    bpf_map_update_elem(&ai_processes, &pid, &ai_flag, BPF_ANY);

    bpf_ringbuf_submit(event, 0);
    return 0;
}

// Monitor memory allocation patterns that might indicate model loading
SEC("kprobe/__kmalloc")
int BPF_KPROBE(kprobe_ai_memory_allocation, size_t size, gfp_t flags)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;

    // Only monitor large allocations from AI processes
    if (size < 100 * 1024 * 1024) // 100MB threshold
        return 0;

    __u32 *ai_flag = bpf_map_lookup_elem(&ai_processes, &pid);
    if (!ai_flag)
        return 0;

    char comm[16];
    bpf_get_current_comm(&comm, sizeof(comm));

    struct ai_model_event *event;
    event = bpf_ringbuf_reserve(&ai_events, sizeof(*event), 0);
    if (!event)
        return 0;

    event->pid = pid;
    event->timestamp = bpf_ktime_get_ns();
    event->action = 1; // inference (assumed for large memory allocation)
    event->threat_level = 0; // low
    event->data_size = size;

    bpf_probe_read_kernel_str(&event->comm, sizeof(event->comm), comm);
    bpf_snprintf(event->description, sizeof(event->description),
                "Large memory allocation - potential model inference (%lu bytes)", size);

    bpf_ringbuf_submit(event, 0);
    return 0;
}

// Monitor process spawning from AI processes (potential privilege escalation)
SEC("tp/sched/sched_process_fork")
int trace_ai_process_fork(struct trace_event_raw_sched_process_fork *ctx)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 parent_pid = pid_tgid >> 32;
    __u32 child_pid = BPF_CORE_READ(ctx, child_pid);

    // Check if parent is an AI process
    __u32 *ai_flag = bpf_map_lookup_elem(&ai_processes, &parent_pid);
    if (!ai_flag)
        return 0;

    char comm[16];
    bpf_get_current_comm(&comm, sizeof(comm));

    struct ai_model_event *event;
    event = bpf_ringbuf_reserve(&ai_events, sizeof(*event), 0);
    if (!event)
        return 0;

    event->pid = parent_pid;
    event->timestamp = bpf_ktime_get_ns();
    event->action = 4; // suspicious
    event->threat_level = 1; // medium
    event->data_size = child_pid;

    bpf_probe_read_kernel_str(&event->comm, sizeof(event->comm), comm);
    bpf_snprintf(event->description, sizeof(event->description),
                "AI process spawned child process (PID: %u)", child_pid);

    // Inherit AI flag for child process
    bpf_map_update_elem(&ai_processes, &child_pid, ai_flag, BPF_ANY);

    bpf_ringbuf_submit(event, 0);
    return 0;
}

char _license[] SEC("license") = "GPL";