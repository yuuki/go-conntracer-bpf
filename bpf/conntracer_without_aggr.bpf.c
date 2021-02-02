// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
// Copyright (c) 2020 Yuuki Tsubouchi

#include "vmlinux.h"

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#include "conntracer.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, u32);
	__type(value, struct sock *);
	__uint(map_flags, BPF_F_NO_PREALLOC);
} sockets SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024 /* 256 KB */);
} flows SEC(".maps");

static __always_inline void
insert_flows(pid_t pid, struct sock *sk, __u16 lport, __u8 direction)
{
	struct flow *flow;

	flow = bpf_ringbuf_reserve(&flows, sizeof(*flow), 0);
	if (!flow)
		return;

	flow->ts_us = bpf_ktime_get_ns() / 1000;
	BPF_CORE_READ_INTO(&flow->saddr, sk, __sk_common.skc_rcv_saddr);
	BPF_CORE_READ_INTO(&flow->daddr, sk, __sk_common.skc_daddr);
	flow->lport = lport;
	flow->pid = pid;
	flow->direction = direction;
	bpf_get_current_comm(&flow->task, sizeof(flow->task));

    bpf_ringbuf_submit(flow, 0);
}

SEC("kprobe/tcp_v4_connect")
int BPF_KPROBE(tcp_v4_connect, struct sock *sk)
{
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	__u32 pid = pid_tgid >> 32;
	__u32 tid = pid_tgid;

	bpf_map_update_elem(&sockets, &tid, &sk, BPF_ANY);

	log_debug("kprobe/tcp_v4_connect: pid_tgid:%d\n", pid_tgid);
	return 0;
}

SEC("kretprobe/tcp_v4_connect")
int BPF_KRETPROBE(tcp_v4_connect_ret, int ret)
{
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	__u32 pid = pid_tgid >> 32;
	__u32 tid = pid_tgid;
	__u16 dport = 0;

	struct sock** skpp = bpf_map_lookup_elem(&sockets, &tid);
	if (!skpp)
		return 0;

	if (ret)
		goto end;

	struct sock* sk = *skpp;

	BPF_CORE_READ_INTO(&dport, sk, __sk_common.skc_dport);

	insert_flows(pid, sk, dport, FLOW_ACTIVE);

end:
	bpf_map_delete_elem(&sockets, &tid);
	log_debug("kretprobe/tcp_v4_connect: pid_tgid:%d, dport:%d\n", pid_tgid, dport);
	return 0;
}

SEC("kretprobe/inet_csk_accept")
int BPF_KRETPROBE(inet_csk_accept_ret, struct sock *sk)
{
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	__u32 pid = pid_tgid >> 32;
	__u16 lport = 0;

	if (!sk)
		return 0;

	BPF_CORE_READ_INTO(&lport, sk, __sk_common.skc_num);

	insert_flows(pid, sk, lport, FLOW_PASSIVE);

	log_debug("kretprobe/inet_csk_accept: pid_tgid:%d, lport:%d\n", pid_tgid, lport);
	return 0;
}
