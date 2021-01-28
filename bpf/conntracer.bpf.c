// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
// Copyright (c) 2020 Yuuki Tsubouchi

#include "vmlinux.h"

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#include "conntracer.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

/* Helper to output debug logs to /sys/kernel/debug/tracing/trace_pipe
 */
#if DEBUG == 1
#define log_debug(fmt, ...)                                        \
    ({                                                             \
        char ____fmt[] = fmt;                                      \
        bpf_trace_printk(____fmt, sizeof(____fmt), ##__VA_ARGS__); \
    })
#else
// No op
#define log_debug(fmt, ...)
#endif

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, u32);
	__type(value, struct sock *);
	__uint(map_flags, BPF_F_NO_PREALLOC);
} sockets SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, u32);
	__type(value, struct sock *);
	__uint(map_flags, BPF_F_NO_PREALLOC);
} udp_recv_sock SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, struct ipv4_flow_key);
	__type(value, struct flow);
	__uint(max_entries, MAX_FLOW_ENTRIES);
	__uint(map_flags, BPF_F_NO_PREALLOC);
} flows SEC(".maps");

static __always_inline void
insert_flows(pid_t pid, struct sock *sk, __u16 lport, __u8 direction)
{
	struct flow flow = {}, *val;
	struct ipv4_flow_key flow_key = {};

	BPF_CORE_READ_INTO(&flow.saddr, sk, __sk_common.skc_rcv_saddr);
	BPF_CORE_READ_INTO(&flow.daddr, sk, __sk_common.skc_daddr);
	flow.lport = lport;
	flow.direction = direction;
	bpf_get_current_comm(flow.task, sizeof(flow.task));

	flow_key.saddr = flow.saddr;
	flow_key.daddr = flow.daddr;
	flow_key.lport = flow.lport;
	flow_key.direction = flow.direction;
	flow_key.l4_proto = IPPROTO_TCP;

	val = bpf_map_lookup_elem(&flows, &flow_key);
	if (val) {
		__u32 *cnt = &(val->stat.connections);
		__atomic_add_fetch(cnt, 1, __ATOMIC_RELAXED);
		return;
	}

	flow.stat.connections = 1;
	bpf_map_update_elem(&flows, &flow_key, &flow, BPF_ANY);
}

static __always_inline void
insert_udp_flows(pid_t pid, struct sock *sk, __u16 lport, __u8 direction)
{
	struct flow flow = {}, *val;
	struct ipv4_flow_key flow_key = {};

	BPF_CORE_READ_INTO(&flow.saddr, sk, __sk_common.skc_rcv_saddr);
	BPF_CORE_READ_INTO(&flow.daddr, sk, __sk_common.skc_daddr);
	flow.lport = lport;
	flow.direction = direction;
	flow.l4_proto = IPPROTO_UDP;
	bpf_get_current_comm(flow.task, sizeof(flow.task));

	flow_key.saddr = flow.saddr;
	flow_key.daddr = flow.daddr;
	flow_key.lport = flow.lport;
	flow_key.direction = flow.direction;
	flow_key.l4_proto = flow.l4_proto;

	bpf_map_update_elem(&flows, &flow_key, &flow, BPF_ANY);
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

SEC("kprobe/udp_recvmsg")
int BPF_KPROBE(udp_recvmsg, struct sock *sk) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();

    bpf_map_update_elem(&udp_recv_sock, &pid_tgid, &sk, BPF_ANY);

    log_debug("kprobe/udp_recvmsg: pid_tgid: %d\n", pid_tgid);
    return 0;
}

SEC("kretprobe/udp_recvmsg")
int BPF_KRETPROBE(udp_recvmsg_ret, int ret) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
	__u32 pid = pid_tgid >> 32;
	__u16 lport;

	struct sock** skpp = bpf_map_lookup_elem(&udp_recv_sock, &pid_tgid);
    if (skpp == 0) {
		goto end;
	}
    struct sock* sk = *skpp;

	if (ret)
		goto end;

	BPF_CORE_READ_INTO(&lport, sk, __sk_common.skc_num);

	insert_udp_flows(pid, sk, lport, FLOW_PASSIVE);

    log_debug("kretprobe/udp_recvmsg: pid_tgid: %d, return: %d\n", pid_tgid, copied);
end:
	bpf_map_delete_elem(&udp_recv_sock, &pid_tgid);
    return 0;
}
