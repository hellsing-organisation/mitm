// SPDX-License-Identifier: (MIT OR GPL-2.0)
#ifndef __BPF_HELPERS__
#define __BPF_HELPERS__

typedef unsigned char __u8;
typedef unsigned short __u16;
typedef unsigned int __u32;
typedef unsigned long long __u64;
typedef signed char __s8;
typedef short __s16;
typedef int __s32;
typedef long long __s64;

#define SEC(x) __attribute__((section(x), used))

#ifndef __uint
#define __uint(name, val) int (*name)[val]
#endif
#ifndef __type
#define __type(name, val) typeof(val) *name
#endif
#ifndef __array
#define __array(name, val) typeof(val) *name[]
#endif

#define BPF_MAP_TYPE_ARRAY 2
#define BPF_MAP_TYPE_PERCPU_ARRAY 6
#define BPF_MAP_TYPE_RINGBUF 27

#define __always_inline inline __attribute__((always_inline))

static __u64 (*bpf_ktime_get_ns)(void) = (void *)5;
static void *(*bpf_map_lookup_elem)(void *map, const void *key) = (void *)1;
static long (*bpf_map_update_elem)(void *map, const void *key, const void *value, __u64 flags) = (void *)2;

#define BPF_ANY 0
static __u64 (*bpf_get_current_pid_tgid)(void) = (void *)14;
static __u64 (*bpf_get_current_uid_gid)(void) = (void *)15;
static __u32 (*bpf_get_current_comm)(void *buf, __u32 size) = (void *)16;
static long (*bpf_probe_read_kernel)(void *dst, __u32 size, const void *unsafe_ptr) = (void *)113;
static __u64 (*bpf_ringbuf_output)(void *ringbuf, void *data, __u64 size, __u64 flags) = (void *)130;

#endif
