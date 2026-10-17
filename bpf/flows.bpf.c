// SPDX-License-Identifier: (MIT OR GPL-2.0)
#include "include/bpf_helpers.h"

#define AF_INET 2
#define AF_INET6 10
#define TCP_SYN_SENT 2
#define IPPROTO_TCP 6

char LICENSE[] SEC("license") = "Dual MIT/GPL";

struct flow_event_t {
    __u64 ts;
    __u32 pid;
    __u32 uid;
    char comm[16];
    __u16 family;
    __u16 sport;
    __u16 dport;
    __u16 _pad;
    __u8 saddr[4];
    __u8 daddr[4];
    __u8 saddr6[16];
    __u8 daddr6[16];
} __attribute__((packed));

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} events SEC(".maps");

struct trace_event_raw_inet_sock_set_state {
    unsigned short common_type;
    unsigned char common_flags;
    unsigned char common_preempt_count;
    int common_pid;
    const void *skbaddr;
    const void *skaddr;
    int oldstate;
    int newstate;
    __u16 sport;
    __u16 dport;
    __u16 family;
    __u16 protocol;
    __u8 saddr[4];
    __u8 daddr[4];
    __u8 saddr_v6[16];
    __u8 daddr_v6[16];
};

SEC("tracepoint/inet/inet_sock_set_state")
int inet_sock_set_state(struct trace_event_raw_inet_sock_set_state *ctx)
{
    if (ctx->newstate != TCP_SYN_SENT || ctx->protocol != IPPROTO_TCP)
        return 0;

    struct flow_event_t ev = {};
    ev.ts = bpf_ktime_get_ns();
    ev.pid = bpf_get_current_pid_tgid() >> 32;
    ev.uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    bpf_get_current_comm(ev.comm, sizeof(ev.comm));
    ev.family = ctx->family;
    ev.sport = ctx->sport;
    ev.dport = ctx->dport;
    __builtin_memcpy(ev.saddr, ctx->saddr, 4);
    __builtin_memcpy(ev.daddr, ctx->daddr, 4);
    __builtin_memcpy(ev.saddr6, ctx->saddr_v6, 16);
    __builtin_memcpy(ev.daddr6, ctx->daddr_v6, 16);

    bpf_ringbuf_output(&events, &ev, sizeof(ev), 0);
    return 0;
}
