// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
// Copyright (c) 2020 Yuuki Tsubouchi

#include "vmlinux.h"

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#include "conntracer.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

/* Define here, because there are conflicts with include files */
#define AF_INET		2
#define AF_INET6	10

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, u32);
	__type(value, struct sock *);
	__uint(map_flags, BPF_F_NO_PREALLOC);
} sockets SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__uint(key_size, sizeof(u32));
	__uint(value_size, sizeof(u32));
} events SEC(".maps");

static __always_inline void
trace_v4(struct pt_regs *ctx, pid_t pid, struct sock *sk, __u16 dport)
{
	struct event event = {};

	event.af = AF_INET;
	event.pid = pid;
	event.uid = bpf_get_current_uid_gid();
	event.ts_us = bpf_ktime_get_ns() / 1000;
	BPF_CORE_READ_INTO(&event.saddr_v4, sk, __sk_common.skc_rcv_saddr);
	BPF_CORE_READ_INTO(&event.daddr_v4, sk, __sk_common.skc_daddr);
	event.dport = dport;
	bpf_get_current_comm(event.task, sizeof(event.task));

	bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU,
			      &event, sizeof(event));
}

static __always_inline int
enter_tcp_connect(struct pt_regs *ctx, struct sock *sk)
{
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	__u32 pid = pid_tgid >> 32;
	__u32 tid = pid_tgid;
	__u32 uid;

	bpf_printk("enter_tcp_connect, pid: %d, uid: %d\n", pid, uid);

	bpf_map_update_elem(&sockets, &pid, &sk, 0);

	return 0;
}

static __always_inline int
exit_tcp_connect(struct pt_regs *ctx, int ret)
{
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	__u32 pid = pid_tgid >> 32;
	__u32 tid = pid_tgid;
	struct sock **skpp;
	struct sock *sk;
	__u16 dport;

	skpp = bpf_map_lookup_elem(&sockets, &tid);
	if (!skpp)
		return 0;

	if (ret)
		goto end;

	sk = *skpp;

	BPF_CORE_READ_INTO(&dport, sk, __sk_common.skc_dport);

	trace_v4(ctx, pid, sk, dport);

end:
	bpf_map_delete_elem(&sockets, &tid);
	return 0;
}

SEC("kprobe/tcp_v4_connect")
int BPF_KPROBE(tcp_v4_connect, struct sock *sk)
{
	return enter_tcp_connect(ctx, sk);
}

SEC("kretprobe/tcp_v4_connect")
int BPF_KRETPROBE(tcp_v4_connect_ret, int ret)
{
	return exit_tcp_connect(ctx, ret);
}
