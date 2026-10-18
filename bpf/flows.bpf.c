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
// file and injects offsets through the cfg array map.
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
    __uint(max_entries, 5);
    __type(key, __u32);
    __type(value, __u64);
} stats SEC(".maps");

enum {
    STAT_CALLS = 0,
    STAT_SYN = 1,
    STAT_FAMILY_OK = 2,
    STAT_RB_FAIL = 3,
    STAT_EMIT = 4,
};

// At SYN_SENT the ephemeral source port is not bound yet (inet_hash_connect
// runs after tcp_set_state(SYN_SENT)), so the record's sport is 0. We stash
// {pid, uid, comm} keyed by (family, daddr, dport) at SYN_SENT and emit the
// completed flow event on the first subsequent transition of the same socket,
// when sport is populated.
struct flow_key_t {
    __u32 daddr4;
    __u8 daddr6[16];
    __u16 dport;
    __u16 family;
} __attribute__((packed));

struct stash_val {
    __u32 pid;
    __u32 uid;
    __u64 ts;
    char comm[16];
};

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 16384);
    __type(key, struct flow_key_t);
    __type(value, struct stash_val);
} pending SEC(".maps");

static __always_inline void stat_add(__u32 idx) {
    __u64 *c = bpf_map_lookup_elem(&stats, &idx);
    if (c)
        (*c)++;
}

static __always_inline int emit_flow(void *ctx, struct offsets_cfg *o,
                                     __u32 pid, __u32 uid, __u64 ts,
                                     const char comm[16]) {
    struct flow_event_t ev = {};
    ev.ts = ts;
    ev.pid = pid;
    ev.uid = uid;
    __builtin_memcpy(ev.comm, comm, 16);
    ev.family = 0;
    bpf_probe_read_kernel(&ev.family, sizeof(ev.family), (char *)ctx + o->family);
    if (ev.family != AF_INET && ev.family != AF_INET6)
        return 0;
    bpf_probe_read_kernel(&ev.sport, sizeof(ev.sport), (char *)ctx + o->sport);
    bpf_probe_read_kernel(&ev.dport, sizeof(ev.dport), (char *)ctx + o->dport);
    if (ev.sport == 0 || ev.dport == 0)
        return 0;
    if (ev.family == AF_INET) {
        bpf_probe_read_kernel(ev.saddr, sizeof(ev.saddr), (char *)ctx + o->saddr);
        bpf_probe_read_kernel(ev.daddr, sizeof(ev.daddr), (char *)ctx + o->daddr);
    } else {
        bpf_probe_read_kernel(ev.saddr6, sizeof(ev.saddr6), (char *)ctx + o->saddr6);
        bpf_probe_read_kernel(ev.daddr6, sizeof(ev.daddr6), (char *)ctx + o->daddr6);
    }
    if (bpf_ringbuf_output(&events, &ev, sizeof(ev), 0) != 0)
        stat_add(STAT_RB_FAIL);
    stat_add(STAT_EMIT);
    return 0;
}

SEC("tracepoint/sock_set_state")
int inet_sock_set_state(void *ctx)
{
    stat_add(STAT_CALLS);

    __u32 zero = 0;
    struct offsets_cfg *o = bpf_map_lookup_elem(&cfg, &zero);
    if (!o)
        return 0;

    int newstate = 0;
    __u16 protocol = 0, family = 0, dport = 0, sport = 0;
    bpf_probe_read_kernel(&newstate, sizeof(newstate), (char *)ctx + o->newstate);
    bpf_probe_read_kernel(&protocol, sizeof(protocol), (char *)ctx + o->protocol);
    bpf_probe_read_kernel(&family, sizeof(family), (char *)ctx + o->family);
    bpf_probe_read_kernel(&dport, sizeof(dport), (char *)ctx + o->dport);
    bpf_probe_read_kernel(&sport, sizeof(sport), (char *)ctx + o->sport);
    if (protocol != IPPROTO_TCP)
        return 0;
    if (family != AF_INET && family != AF_INET6)
        return 0;

    struct flow_key_t key = {};
    key.family = family;
    key.dport = dport;
    if (family == AF_INET)
        bpf_probe_read_kernel(&key.daddr4, sizeof(key.daddr4), (char *)ctx + o->daddr);
    else
        bpf_probe_read_kernel(key.daddr6, sizeof(key.daddr6), (char *)ctx + o->daddr6);

    if (newstate == TCP_SYN_SENT) {
        stat_add(STAT_SYN);
        stat_add(STAT_FAMILY_OK);
        if (sport != 0) {
            // pre-bound socket: emit immediately
            __u32 pid = bpf_get_current_pid_tgid() >> 32;
            __u32 uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
            __u64 ts = bpf_ktime_get_ns();
            char comm[16] = {};
            bpf_get_current_comm(comm, sizeof(comm));
            return emit_flow(ctx, o, pid, uid, ts, comm);
        }
        struct stash_val sv = {};
        sv.pid = bpf_get_current_pid_tgid() >> 32;
        sv.uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
        sv.ts = bpf_ktime_get_ns();
        bpf_get_current_comm(sv.comm, sizeof(sv.comm));
        bpf_map_update_elem(&pending, &key, &sv, BPF_ANY);
        return 0;
    }

    // join: first subsequent transition of a pending outbound connect
    struct stash_val *sv = bpf_map_lookup_elem(&pending, &key);
    if (!sv)
        return 0;
    if (sport == 0)
        return 0;
    emit_flow(ctx, o, sv->pid, sv->uid, sv->ts, sv->comm);
    bpf_map_delete_elem(&pending, &key);
    return 0;
}
