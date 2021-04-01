// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
// Copyright (c) 2020 Yuuki Tsubouchi

#include "vmlinux.h"

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>

#include "conntracer.h"
#include "maps.h"
#include "port_binding.h"
#include "conntracer_bpf_read.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

#define AF_INET		2
#define AF_INET6	10

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, struct ipv4_flow_key);
	__type(value, struct aggregated_flow);
	__uint(max_entries, MAX_FLOW_ENTRIES);
	__uint(map_flags, BPF_F_NO_PREALLOC);
} flows SEC(".maps");

static __always_inline void
insert_tcp_flows(pid_t pid, struct sock *sk, __u16 lport, __u8 direction)
{
	struct aggregated_flow flow = {}, *val;
	struct ipv4_flow_key flow_key = {};

	BPF_CORE_READ_INTO(&flow.saddr, sk, __sk_common.skc_rcv_saddr);
	BPF_CORE_READ_INTO(&flow.daddr, sk, __sk_common.skc_daddr);
	flow.lport = lport;
	flow.pid = pid;
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
insert_udp_flows(pid_t pid, struct ipv4_flow_key* flow_key)
{
	struct aggregated_flow flow = {};

	flow.saddr = flow_key->saddr;
	flow.daddr = flow_key->daddr;
	flow.lport = flow_key->lport;
	flow.direction = flow_key->direction;
	flow.l4_proto = flow_key->l4_proto;
	flow.pid = pid;
	bpf_get_current_comm(flow.task, sizeof(flow.task));

	bpf_map_update_elem(&flows, flow_key, &flow, BPF_ANY);
}

SEC("kprobe/tcp_v4_connect")
int BPF_KPROBE(tcp_v4_connect, struct sock *sk)
{
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	__u32 pid = pid_tgid >> 32;
	__u32 tid = pid_tgid;

	bpf_map_update_elem(&tcp_connect_sockets, &tid, &sk, BPF_ANY);

	log_debug("kprobe/tcp_v4_connect: pid_tgid:%u\n", pid_tgid);
	return 0;
}

SEC("kretprobe/tcp_v4_connect")
int BPF_KRETPROBE(tcp_v4_connect_ret, int ret)
{
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	__u32 pid = pid_tgid >> 32;
	__u32 tid = pid_tgid;
	__u16 dport = 0;

	struct sock** skpp = bpf_map_lookup_elem(&tcp_connect_sockets, &tid);
	if (!skpp)
		return 0;

	if (ret)
		goto end;

	struct sock* sk = *skpp;

	BPF_CORE_READ_INTO(&dport, sk, __sk_common.skc_dport);

	insert_tcp_flows(pid, sk, dport, FLOW_ACTIVE);

	log_debug("kretprobe/tcp_v4_connect: dport:%u, tid:%u\n", dport, pid_tgid);
end:
	bpf_map_delete_elem(&tcp_connect_sockets, &tid);
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

	insert_tcp_flows(pid, sk, lport, FLOW_PASSIVE);

	log_debug("kretprobe/inet_csk_accept: lport:%u,pid_tgid:%u\n", pid_tgid, lport);
	return 0;
}

// struct sock with udp_sendmsg may not miss ip addresses on listening socket.
// Addresses are retrieved from struct flowi4 with ip_make_skb.
// https://github.com/DataDog/datadog-agent/pull/6307
SEC("kprobe/ip_make_skb")
int BPF_KPROBE(ip_make_skb, struct sock *sk, struct flowi4 *flw4) {
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	__u32 pid = pid_tgid >> 32;
	struct ipv4_flow_key flow_key = {};

	read_flow_for_udp_send(&flow_key, sk, flw4);
	insert_udp_flows(pid, &flow_key);

	log_debug("kprobe/ip_make_skb: lport:%u, tgid:%u\n",
		flow_key.lport, pid_tgid);
	return 0;
}

// struct sock with udp_recvmsg may not miss ip addresses on listening socket.
// Addresses are retrieved from arguments of skb_consume_udp.
SEC("kprobe/skb_consume_udp")
int BPF_KPROBE(skb_consume_udp, struct sock *sk, struct sk_buff *skb) {
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	__u32 pid = pid_tgid >> 32;
	struct ipv4_flow_key flow_key = {};

	read_flow_for_udp_recv(&flow_key, sk, skb);
	insert_udp_flows(pid, &flow_key);

	log_debug("kprobe/skb_consume_udp: sport:%u, dport:%u, tid:%u\n",
		flow_key.lport, pid_tgid);
    return 0;
}


// for tracking UDP listening state
SEC("tracepoint/syscalls/sys_enter_socket")
int tracepoint__syscalls__sys_enter_socket(struct trace_event_raw_sys_enter* ctx) {
	__u64 tid = bpf_get_current_pid_tgid();
	int family = (int)ctx->args[0];
	int type = (int)ctx->args[1];
	log_debug("tp/sys_enter_socket: family=%u, type=%u, tid=%u\n", family, type, tid);

	return sys_enter_socket(family, type, tid);
}

// for tracking UDP listening state
SEC("tracepoint/syscalls/sys_exit_socket")
int tracepoint__syscalls__sys_exit_socket(struct trace_event_raw_sys_exit* ctx) {
    __u64 tid = bpf_get_current_pid_tgid();
    log_debug("tp/sys_exit_socket: fd=%d, tid=%u\n", ctx->ret, tid);

	return sys_exit_socket(ctx->ret, tid);
}

SEC("tracepoint/syscalls/sys_enter_bind")
int tracepoint__syscalls__sys_enter_bind(struct trace_event_raw_sys_enter* ctx) {
    __u64 tid = bpf_get_current_pid_tgid();
	int fd = (int)ctx->args[0];
	const struct sockaddr *addr = (const struct sockaddr *)ctx->args[1];
    log_debug("tp/sys_enter_bind: fd=%u, addr=%x, tid=%u\n", fd, addr, tid);
	return sys_enter_bind(fd, addr, tid);

}

SEC("tracepoint/syscalls/sys_exit_bind")
int tracepoint__syscalls__sys_exit_bind(struct trace_event_raw_sys_exit* ctx) {
    __u64 tid = bpf_get_current_pid_tgid();
    log_debug("tp/sys_exit_bind: ret=%d, tid=%u\n", ctx->ret, tid);
	return sys_exit_bind(ctx->ret, tid);
}
