//go:build ignore

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#define MAX_ADDR_LEN 16

// Network event structure
struct network_event {
    __u32 pid;
    __u64 timestamp;
    __u32 action;       // 0=connect, 1=bind, 2=listen, 3=accept, 4=close
    __u32 protocol;     // IPPROTO_TCP, IPPROTO_UDP
    __u8 local_addr[MAX_ADDR_LEN];
    __u16 local_port;
    __u8 remote_addr[MAX_ADDR_LEN];
    __u16 remote_port;
    __u32 family;       // AF_INET, AF_INET6
    __u64 bytes_sent;
    __u64 bytes_recv;
    char comm[16];
};

// Ring buffer for network events
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} network_events SEC(".maps");

// Connection tracking
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u64);  // socket address
    __type(value, struct network_event);
} connections SEC(".maps");

// Suspicious connection detection
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 512);
    __type(key, __u32);  // IP address
    __type(value, __u32); // connection count
} suspicious_ips SEC(".maps");

// Helper function to extract IP address from sockaddr
static __always_inline int extract_sockaddr(struct sockaddr *addr,
                                           struct network_event *event)
{
    if (!addr)
        return -1;

    __u16 family;
    bpf_probe_read_kernel(&family, sizeof(family), &addr->sa_family);

    event->family = family;

    if (family == AF_INET) {
        struct sockaddr_in *addr_in = (struct sockaddr_in *)addr;
        bpf_probe_read_kernel(&event->local_addr[0], 4, &addr_in->sin_addr);
        bpf_probe_read_kernel(&event->local_port, sizeof(__u16), &addr_in->sin_port);
        event->local_port = bpf_ntohs(event->local_port);
    } else if (family == AF_INET6) {
        struct sockaddr_in6 *addr_in6 = (struct sockaddr_in6 *)addr;
        bpf_probe_read_kernel(&event->local_addr[0], 16, &addr_in6->sin6_addr);
        bpf_probe_read_kernel(&event->local_port, sizeof(__u16), &addr_in6->sin6_port);
        event->local_port = bpf_ntohs(event->local_port);
    }

    return 0;
}

// Tracepoint for socket connect
SEC("tp/syscalls/sys_enter_connect")
int trace_sys_enter_connect(struct trace_event_raw_sys_enter *ctx)
{
    struct network_event *event;
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;

    event = bpf_ringbuf_reserve(&network_events, sizeof(*event), 0);
    if (!event)
        return 0;

    event->pid = pid;
    event->timestamp = bpf_ktime_get_ns();
    event->action = 0; // connect
    event->bytes_sent = 0;
    event->bytes_recv = 0;

    bpf_get_current_comm(&event->comm, sizeof(event->comm));

    // Get socket address
    struct sockaddr *addr = (struct sockaddr *)ctx->args[1];
    extract_sockaddr(addr, event);

    // Check for suspicious connections
    if (event->family == AF_INET) {
        __u32 remote_ip = *(__u32 *)&event->local_addr[0];
        __u32 *count = bpf_map_lookup_elem(&suspicious_ips, &remote_ip);
        if (count) {
            (*count)++;
        } else {
            __u32 initial_count = 1;
            bpf_map_update_elem(&suspicious_ips, &remote_ip, &initial_count, BPF_ANY);
        }
    }

    bpf_ringbuf_submit(event, 0);
    return 0;
}

// Tracepoint for socket bind
SEC("tp/syscalls/sys_enter_bind")
int trace_sys_enter_bind(struct trace_event_raw_sys_enter *ctx)
{
    struct network_event *event;
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;

    event = bpf_ringbuf_reserve(&network_events, sizeof(*event), 0);
    if (!event)
        return 0;

    event->pid = pid;
    event->timestamp = bpf_ktime_get_ns();
    event->action = 1; // bind
    event->bytes_sent = 0;
    event->bytes_recv = 0;

    bpf_get_current_comm(&event->comm, sizeof(event->comm));

    // Get socket address
    struct sockaddr *addr = (struct sockaddr *)ctx->args[1];
    extract_sockaddr(addr, event);

    bpf_ringbuf_submit(event, 0);
    return 0;
}

// Tracepoint for socket listen
SEC("tp/syscalls/sys_enter_listen")
int trace_sys_enter_listen(struct trace_event_raw_sys_enter *ctx)
{
    struct network_event *event;
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;

    event = bpf_ringbuf_reserve(&network_events, sizeof(*event), 0);
    if (!event)
        return 0;

    event->pid = pid;
    event->timestamp = bpf_ktime_get_ns();
    event->action = 2; // listen
    event->bytes_sent = 0;
    event->bytes_recv = 0;

    bpf_get_current_comm(&event->comm, sizeof(event->comm));

    bpf_ringbuf_submit(event, 0);
    return 0;
}

// Tracepoint for socket accept
SEC("tp/syscalls/sys_enter_accept4")
int trace_sys_enter_accept4(struct trace_event_raw_sys_enter *ctx)
{
    struct network_event *event;
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;

    event = bpf_ringbuf_reserve(&network_events, sizeof(*event), 0);
    if (!event)
        return 0;

    event->pid = pid;
    event->timestamp = bpf_ktime_get_ns();
    event->action = 3; // accept
    event->bytes_sent = 0;
    event->bytes_recv = 0;

    bpf_get_current_comm(&event->comm, sizeof(event->comm));

    bpf_ringbuf_submit(event, 0);
    return 0;
}

// Tracepoint for socket send
SEC("tp/syscalls/sys_enter_sendto")
int trace_sys_enter_sendto(struct trace_event_raw_sys_enter *ctx)
{
    struct network_event *event;
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;

    // Only track large data transfers for potential exfiltration detection
    size_t len = (size_t)ctx->args[2];
    if (len < 1024) // Skip small transfers
        return 0;

    event = bpf_ringbuf_reserve(&network_events, sizeof(*event), 0);
    if (!event)
        return 0;

    event->pid = pid;
    event->timestamp = bpf_ktime_get_ns();
    event->action = 5; // send (custom action)
    event->bytes_sent = len;
    event->bytes_recv = 0;

    bpf_get_current_comm(&event->comm, sizeof(event->comm));

    // Get destination address if provided
    struct sockaddr *addr = (struct sockaddr *)ctx->args[4];
    if (addr) {
        extract_sockaddr(addr, event);
    }

    bpf_ringbuf_submit(event, 0);
    return 0;
}

// Kprobe for tracking TCP data transmission
SEC("kprobe/tcp_sendmsg")
int BPF_KPROBE(kprobe_tcp_sendmsg, struct sock *sk, struct msghdr *msg, size_t size)
{
    struct network_event *event;
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;

    // Only track significant data transfers
    if (size < 4096)
        return 0;

    event = bpf_ringbuf_reserve(&network_events, sizeof(*event), 0);
    if (!event)
        return 0;

    event->pid = pid;
    event->timestamp = bpf_ktime_get_ns();
    event->action = 6; // tcp_send (custom action)
    event->bytes_sent = size;
    event->bytes_recv = 0;
    event->protocol = IPPROTO_TCP;

    bpf_get_current_comm(&event->comm, sizeof(event->comm));

    // Extract socket information
    if (sk) {
        __u16 family = BPF_CORE_READ(sk, __sk_common.skc_family);
        event->family = family;

        if (family == AF_INET) {
            __u32 saddr = BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr);
            __u32 daddr = BPF_CORE_READ(sk, __sk_common.skc_daddr);
            __u16 sport = BPF_CORE_READ(sk, __sk_common.skc_num);
            __u16 dport = BPF_CORE_READ(sk, __sk_common.skc_dport);

            *(__u32 *)&event->local_addr[0] = saddr;
            *(__u32 *)&event->remote_addr[0] = daddr;
            event->local_port = sport;
            event->remote_port = bpf_ntohs(dport);
        }
    }

    bpf_ringbuf_submit(event, 0);
    return 0;
}

// AI-specific network monitoring - detect model exfiltration patterns
SEC("kprobe/tcp_sendmsg")
int BPF_KPROBE(kprobe_ai_exfiltration_detect, struct sock *sk, struct msghdr *msg, size_t size)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;

    // Detect potential model exfiltration (large file transfers)
    if (size > 1024 * 1024) { // 1MB threshold
        char comm[16];
        bpf_get_current_comm(&comm, sizeof(comm));

        // Check if this is an AI-related process
        if (bpf_strncmp(comm, "python", 6) == 0 ||
            bpf_strncmp(comm, "pytorch", 7) == 0 ||
            bpf_strncmp(comm, "tensorflow", 10) == 0) {

            struct network_event *event;
            event = bpf_ringbuf_reserve(&network_events, sizeof(*event), 0);
            if (!event)
                return 0;

            event->pid = pid;
            event->timestamp = bpf_ktime_get_ns();
            event->action = 7; // ai_exfiltration_alert (custom action)
            event->bytes_sent = size;
            event->protocol = IPPROTO_TCP;

            bpf_probe_read_kernel_str(&event->comm, sizeof(event->comm), comm);

            bpf_ringbuf_submit(event, 0);
        }
    }

    return 0;
}

char _license[] SEC("license") = "GPL";