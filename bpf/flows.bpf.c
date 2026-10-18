// SPDX-License-Identifier: (MIT OR GPL-2.0)
#include "include/bpf_helpers.h"

#define AF_INET 2
#define AF_INET6 10
#define TCP_SYN_SENT 2
#define IPPROTO_TCP 6

char LICENSE[] SEC("license") = "Dual MIT/GPL";

// Field offsets within the inet_sock_set_state tracepoint record, rewritten
// from the live kernel's "format" file at load time (layouts drift across
// kernel versions: the event moved from group inet to sock and lost skbaddr
// in 6.18). Defaults below match the pre-6.18 layout only so the object
// links standalone; the loader always rewrites them.
volatile const __u32 off_oldstate = 24;
volatile const __u32 off_newstate = 28;
volatile const __u32 off_protocol = 38;
volatile const __u32 off_sport = 32;
volatile const __u32 off_dport = 34;
volatile const __u32 off_family = 36;
volatile const __u32 off_saddr = 40;
volatile const __u32 off_daddr = 44;
volatile const __u32 off_saddr6 = 48;
volatile const __u32 off_daddr6 = 64;

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

SEC("tracepoint/sock_set_state")
int inet_sock_set_state(void *ctx)
{
    int newstate = 0, protocol = 0;
    bpf_probe_read_kernel(&newstate, sizeof(newstate), (char *)ctx + off_newstate);
    bpf_probe_read_kernel(&protocol, sizeof(protocol), (char *)ctx + off_protocol);
    if (newstate != TCP_SYN_SENT || protocol != IPPROTO_TCP)
        return 0;

    struct flow_event_t ev = {};
    ev.ts = bpf_ktime_get_ns();
    ev.pid = bpf_get_current_pid_tgid() >> 32;
    ev.uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    bpf_get_current_comm(ev.comm, sizeof(ev.comm));
    bpf_probe_read_kernel(&ev.family, sizeof(ev.family), (char *)ctx + off_family);
    bpf_probe_read_kernel(&ev.sport, sizeof(ev.sport), (char *)ctx + off_sport);
    bpf_probe_read_kernel(&ev.dport, sizeof(ev.dport), (char *)ctx + off_dport);
    bpf_probe_read_kernel(ev.saddr, sizeof(ev.saddr), (char *)ctx + off_saddr);
    bpf_probe_read_kernel(ev.daddr, sizeof(ev.daddr), (char *)ctx + off_daddr);
    bpf_probe_read_kernel(ev.saddr6, sizeof(ev.saddr6), (char *)ctx + off_saddr6);
    bpf_probe_read_kernel(ev.daddr6, sizeof(ev.daddr6), (char *)ctx + off_daddr6);

    if (ev.family != AF_INET && ev.family != AF_INET6)
        return 0;

    bpf_ringbuf_output(&events, &ev, sizeof(ev), 0);
    return 0;
}
