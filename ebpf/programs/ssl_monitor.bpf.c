//go:build ignore

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#define MAX_DATA_SIZE 4096

// SSL event structure
struct ssl_event {
    __u32 pid;
    __u32 tid;
    __u64 timestamp;
    __u32 action;      // 0=handshake, 1=read, 2=write
    __u32 data_len;
    __u8 data[MAX_DATA_SIZE];
    char comm[16];
};

// Ring buffer for SSL events
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} ssl_events SEC(".maps");

// SSL function tracking
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u32);
    __type(value, struct ssl_event);
} ssl_ctx SEC(".maps");

// OpenSSL SSL_read hook
SEC("uprobe/SSL_read")
int BPF_KPROBE(ssl_read_enter, void *ssl, void *buf, int num)
{
    struct ssl_event *event;
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;
    __u32 tid = (__u32)pid_tgid;

    event = bpf_ringbuf_reserve(&ssl_events, sizeof(*event), 0);
    if (!event)
        return 0;

    event->pid = pid;
    event->tid = tid;
    event->timestamp = bpf_ktime_get_ns();
    event->action = 1; // read
    event->data_len = num;

    bpf_get_current_comm(&event->comm, sizeof(event->comm));

    // Try to read some data (limited by eBPF constraints)
    int read_size = num > MAX_DATA_SIZE ? MAX_DATA_SIZE : num;
    if (buf && read_size > 0) {
        bpf_probe_read_user(&event->data, read_size, buf);
    }

    bpf_ringbuf_submit(event, 0);
    return 0;
}

// OpenSSL SSL_write hook
SEC("uprobe/SSL_write")
int BPF_KPROBE(ssl_write_enter, void *ssl, void *buf, int num)
{
    struct ssl_event *event;
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;
    __u32 tid = (__u32)pid_tgid;

    event = bpf_ringbuf_reserve(&ssl_events, sizeof(*event), 0);
    if (!event)
        return 0;

    event->pid = pid;
    event->tid = tid;
    event->timestamp = bpf_ktime_get_ns();
    event->action = 2; // write
    event->data_len = num;

    bpf_get_current_comm(&event->comm, sizeof(event->comm));

    // Try to read some data
    int read_size = num > MAX_DATA_SIZE ? MAX_DATA_SIZE : num;
    if (buf && read_size > 0) {
        bpf_probe_read_user(&event->data, read_size, buf);
    }

    bpf_ringbuf_submit(event, 0);
    return 0;
}

// GnuTLS hooks
SEC("uprobe/gnutls_record_recv")
int BPF_KPROBE(gnutls_recv_enter, void *session, void *data, __u32 data_size)
{
    struct ssl_event *event;
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;
    __u32 tid = (__u32)pid_tgid;

    event = bpf_ringbuf_reserve(&ssl_events, sizeof(*event), 0);
    if (!event)
        return 0;

    event->pid = pid;
    event->tid = tid;
    event->timestamp = bpf_ktime_get_ns();
    event->action = 1; // read
    event->data_len = data_size;

    bpf_get_current_comm(&event->comm, sizeof(event->comm));

    int read_size = data_size > MAX_DATA_SIZE ? MAX_DATA_SIZE : data_size;
    if (data && read_size > 0) {
        bpf_probe_read_user(&event->data, read_size, data);
    }

    bpf_ringbuf_submit(event, 0);
    return 0;
}

SEC("uprobe/gnutls_record_send")
int BPF_KPROBE(gnutls_send_enter, void *session, void *data, __u32 data_size)
{
    struct ssl_event *event;
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;
    __u32 tid = (__u32)pid_tgid;

    event = bpf_ringbuf_reserve(&ssl_events, sizeof(*event), 0);
    if (!event)
        return 0;

    event->pid = pid;
    event->tid = tid;
    event->timestamp = bpf_ktime_get_ns();
    event->action = 2; // write
    event->data_len = data_size;

    bpf_get_current_comm(&event->comm, sizeof(event->comm));

    int read_size = data_size > MAX_DATA_SIZE ? MAX_DATA_SIZE : data_size;
    if (data && read_size > 0) {
        bpf_probe_read_user(&event->data, read_size, data);
    }

    bpf_ringbuf_submit(event, 0);
    return 0;
}

char _license[] SEC("license") = "GPL";