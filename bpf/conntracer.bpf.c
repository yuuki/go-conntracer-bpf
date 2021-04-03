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
	__type(key, struct aggregated_flow_tuple);
	__type(value, struct aggregated_flow);
	__uint(max_entries, MAX_FLOW_ENTRIES);
	__uint(map_flags, BPF_F_NO_PREALLOC);
} flows SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, struct aggregated_flow_tuple);
	__type(value, struct aggregated_flow_stat);
	__uint(max_entries, MAX_FLOW_ENTRIES);
	__uint(map_flags, BPF_F_NO_PREALLOC);
} flow_stats SEC(".maps");

static __always_inline void
insert_tcp_flows(struct aggregated_flow_tuple *tuple, pid_t pid) {
	struct aggregated_flow flow = {}, *val;

	flow.ts_us = bpf_ktime_get_ns() / 1000;
	flow.saddr = tuple->saddr;
	flow.daddr = tuple->daddr;
	flow.lport = tuple->lport;
	flow.pid = pid;
	flow.direction = tuple->direction;
	bpf_get_current_comm(flow.task, sizeof(flow.task));

	bpf_map_update_elem(&flows, tuple, &flow, BPF_ANY);
}

static __always_inline void
insert_udp_flows(pid_t pid, struct aggregated_flow_tuple* tuple)
{
	struct aggregated_flow flow = {};

	flow.saddr = tuple->saddr;
	flow.daddr = tuple->daddr;
	flow.lport = tuple->lport;
	flow.direction = tuple->direction;
	flow.l4_proto = tuple->l4_proto;
	flow.pid = pid;
	bpf_get_current_comm(flow.task, sizeof(flow.task));

	bpf_map_update_elem(&flows, tuple, &flow, BPF_ANY);
}

static __always_inline void
update_message(struct aggregated_flow_tuple* tuple, size_t sent_bytes, size_t recv_bytes)
{
	struct aggregated_flow_stat *val, empty = {};

    __builtin_memset(&empty, 0, sizeof(struct aggregated_flow_stat));
	bpf_map_update_elem(&flow_stats, tuple, &empty, BPF_NOEXIST);

	val = bpf_map_lookup_elem(&flow_stats, tuple);
	if (!val) return;
	val->ts_us = bpf_ktime_get_ns() / 1000;

	if (sent_bytes) {
		__atomic_add_fetch(&val->sent_bytes, sent_bytes, __ATOMIC_RELAXED);
	}
	if (recv_bytes) {
		__atomic_add_fetch(&val->recv_bytes, recv_bytes, __ATOMIC_RELAXED);
	}
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

	struct aggregated_flow_tuple tuple = {};
	read_aggr_flow_tuple_for_tcp(&tuple, sk, FLOW_ACTIVE);
	insert_tcp_flows(&tuple, pid);
	update_message(&tuple, 0, 0);

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

	if (!sk) return 0;

	struct aggregated_flow_tuple tuple = {};
	read_aggr_flow_tuple_for_tcp(&tuple, sk, FLOW_PASSIVE);
	insert_tcp_flows(&tuple, pid);
	update_port_binding(tuple.lport);
	update_message(&tuple, 0, 0);

	log_debug("kretprobe/inet_csk_accept: lport:%u, tgid:%u\n", tuple.lport, pid_tgid);
	return 0;
}

SEC("kprobe/tcp_sendmsg")
int BPF_KPROBE(tcp_sendmsg, struct sock* sk, struct msghdr *msg, size_t size) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
	__u32 pid = pid_tgid >> 32;

    struct aggregated_flow_tuple tuple = {};
	read_aggr_flow_tuple_for_tcp(&tuple, sk, FLOW_UNKNOWN);
	update_message(&tuple, size, 0);

    log_debug("kprobe/tcp_sendmsg: size:%d, lport:%u, tgid:%d\n", size, tuple.lport, pid_tgid);
    return 0;
}

SEC("kprobe/tcp_cleanup_rbuf")
int BPF_KPROBE(tcp_cleanup_rbuf, struct sock* sk, int copied) {
    if (copied < 0) {
        return 0;
    }
    __u64 pid_tgid = bpf_get_current_pid_tgid();
	__u32 pid = pid_tgid >> 32;

    struct aggregated_flow_tuple tuple = {};
	read_aggr_flow_tuple_for_tcp(&tuple, sk, FLOW_UNKNOWN);
    update_message(&tuple, 0, copied);

    log_debug("kprobe/tcp_cleanup_rbuf: copied:%d, lport:%u, tgid:%d\n", copied, tuple.lport, pid_tgid);
	return 0;
}

SEC("kprobe/inet_csk_listen_stop")
int BPF_KPROBE(inet_csk_listen_stop, struct sock* sk) {
    __u16 lport = read_sport(sk);
    if (lport == 0) {
        log_debug("kprobe/inet_csk_listen_stop error: lport is 0\n");
        return 0;
    }

    struct port_binding_key pb = {};
    pb.port = lport;
    bpf_map_delete_elem(&tcp_port_binding, &pb);

    log_debug("kprobe/inet_csk_listen_stop: lport: %u\n", lport);
    return 0;
}

// struct sock with udp_sendmsg may not miss ip addresses on listening socket.
// Addresses are retrieved from struct flowi4 with ip_make_skb.
// https://github.com/DataDog/datadog-agent/pull/6307
SEC("kprobe/ip_send_skb")
int BPF_KPROBE(ip_send_skb, struct net *net, struct sk_buff *skb) {
	__u16 protocol = BPF_CORE_READ(skb, protocol);
	if (protocol != IPPROTO_UDP) {
		return 0;
	}

	__u64 pid_tgid = bpf_get_current_pid_tgid();
	__u32 pid = pid_tgid >> 32;
	struct aggregated_flow_tuple tuple = {};
	size_t msglen = 0;

	BPF_CORE_READ_INTO(&msglen, get_udphdr(skb), len);
	msglen = msglen - sizeof(struct udphdr);

	read_flow_for_udp_send(&tuple, skb);
	insert_udp_flows(pid, &tuple);
    update_message(&tuple, msglen, 0);

	log_debug("kprobe/ip_send_skb: lport:%u, msglen:%u, tgid:%u\n",
		tuple.lport, msglen, pid_tgid);
	return 0;
}

// struct sock with udp_recvmsg may not miss ip addresses on listening socket.
// Addresses are retrieved from arguments of skb_consume_udp.
SEC("kprobe/skb_consume_udp")
int BPF_KPROBE(skb_consume_udp, struct sock *sk, struct sk_buff *skb, int len) {
	if (len < 0) {
		return 0;
	}

	__u64 pid_tgid = bpf_get_current_pid_tgid();
	__u32 pid = pid_tgid >> 32;
	struct aggregated_flow_tuple tuple = {};

	read_flow_for_udp_recv(&tuple, sk, skb);
	insert_udp_flows(pid, &tuple);
    update_message(&tuple, 0, len);

	log_debug("kprobe/skb_consume_udp: lport:%u, len:%u, tid:%u\n",
		tuple.lport, len, pid_tgid);
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
