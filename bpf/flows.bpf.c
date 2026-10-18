// SPDX-License-Identifier: (MIT OR GPL-2.0)
#include "include/bpf_helpers.h"

#define AF_INET 2
#define AF_INET6 10
#define TCP_SYN_SENT 2
#define IPPROTO_TCP 6

char LICENSE[] SEC("license") = "Dual MIT/GPL";

// Layout offsets within the inet_sock_set_state tracepoint record. Layouts
// drift across kernel versions (the event moved from group inet to sock and
// lost skbaddr in 6.18), so the userspace loader parses the live "format"
// file and injects offsets through this array map. No .rodata rewriting.
struct offsets_cfg {
    __u32 oldstate;
    __u32 newstate;
    __u32 protocol;
    __u32 sport;
    __u32 dport;
    __u32 family;
    __u32 saddr;
    __u32 daddr;
    __u32 saddr6;
    __u32 daddr6;
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct offsets_cfg);
} cfg SEC(".maps");

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

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 4);
    __type(key, __u32);
    __type(value, __u64);
} stats SEC(".maps");

enum {
    STAT_CALLS = 0,
    STAT_SYN = 1,
    STAT_FAMILY_OK = 2,
    STAT_RB_FAIL = 3,
};

static __always_inline void stat_add(__u32 idx) {
    __u64 *c = bpf_map_lookup_elem(&stats, &idx);
    if (c)
        (*c)++;
}

SEC("tracepoint/sock_set_state")
int inet_sock_set_state(void *ctx)
{
    stat_add(STAT_CALLS);

    __u32 zero = 0;
    struct offsets_cfg *o = bpf_map_lookup_elem(&cfg, &zero);
    if (!o)
        return 0;

    int newstate = 0, protocol = 0;
    __u16 family = 0;
    bpf_probe_read_kernel(&newstate, sizeof(newstate), (char *)ctx + o->newstate);
    bpf_probe_read_kernel(&protocol, sizeof(protocol), (char *)ctx + o->protocol);
    if (newstate != TCP_SYN_SENT || protocol != IPPROTO_TCP)
        return 0;
    stat_add(STAT_SYN);

    bpf_probe_read_kernel(&family, sizeof(family), (char *)ctx + o->family);
    if (family != AF_INET && family != AF_INET6)
        return 0;
    stat_add(STAT_FAMILY_OK);

    struct flow_event_t ev = {};
    ev.ts = bpf_ktime_get_ns();
    ev.pid = bpf_get_current_pid_tgid() >> 32;
    ev.uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    bpf_get_current_comm(ev.comm, sizeof(ev.comm));
    ev.family = family;
    bpf_probe_read_kernel(&ev.sport, sizeof(ev.sport), (char *)ctx + o->sport);
    bpf_probe_read_kernel(&ev.dport, sizeof(ev.dport), (char *)ctx + o->dport);
    bpf_probe_read_kernel(ev.saddr, sizeof(ev.saddr), (char *)ctx + o->saddr);
    bpf_probe_read_kernel(ev.daddr, sizeof(ev.daddr), (char *)ctx + o->daddr);
    bpf_probe_read_kernel(ev.saddr6, sizeof(ev.saddr6), (char *)ctx + o->saddr6);
    bpf_probe_read_kernel(ev.daddr6, sizeof(ev.daddr6), (char *)ctx + o->daddr6);

    if (bpf_ringbuf_output(&events, &ev, sizeof(ev), 0) != 0)
        stat_add(STAT_RB_FAIL);
    return 0;
}
