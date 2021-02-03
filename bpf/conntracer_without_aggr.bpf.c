// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
// Copyright (c) 2020 Yuuki Tsubouchi

#include "vmlinux.h"

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>

#include "conntracer.h"

#define AF_INET		2
#define AF_INET6	10

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, u32);
	__type(value, struct sock *);
	__uint(map_flags, BPF_F_NO_PREALLOC);
} tcp_connect_sockets SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024 /* 256 KB */);
} flows SEC(".maps");

// udp_port_binding is a map for tracking LISNING or CLOSED ports.
// udp_port_binding enables to register entire local ports and 
// insert or update the port number and state at the timing when the port state changes.
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_PORT_BINDING_ENTRIES);
	__type(key, struct port_binding_key);
	__type(value, __u8);		// protocol state
} udp_port_binding SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, __u64);	 // tid | fd
	__type(value, __u8); // bool
	__uint(max_entries, MAX_ENTRIES);
	__uint(map_flags, BPF_F_NO_PREALLOC);
} entering_udp_sockets SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, __u64);	 // tid | fd
	__type(value, __u8); // bool
	__uint(max_entries, MAX_ENTRIES);
} unbound_udp_sockets SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, __u64); // tid
	__type(value, struct bind_args);
} entering_bind SEC(".maps");

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

static __always_inline void
insert_udp_flows(pid_t pid, struct ipv4_flow_key* flow_key)
{
	struct flow *flow;

	flow = bpf_ringbuf_reserve(&flows, sizeof(*flow), 0);
	if (!flow)
		return;

	flow->ts_us = bpf_ktime_get_ns() / 1000;
	flow->saddr = flow_key->saddr;
	flow->daddr = flow_key->daddr;
	flow->lport = flow_key->lport;
	flow->direction = flow_key->direction;
	flow->l4_proto = flow_key->l4_proto;
	flow->pid = pid;
	bpf_get_current_comm(flow->task, sizeof(flow->task));

    bpf_ringbuf_submit(flow, 0);
}

SEC("kprobe/tcp_v4_connect")
int BPF_KPROBE(tcp_v4_connect, struct sock *sk)
{
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	__u32 pid = pid_tgid >> 32;
	__u32 tid = pid_tgid;

	bpf_map_update_elem(&tcp_connect_sockets, &tid, &sk, BPF_ANY);

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

	struct sock** skpp = bpf_map_lookup_elem(&tcp_connect_sockets, &tid);
	if (!skpp)
		return 0;

	if (ret)
		goto end;

	struct sock* sk = *skpp;

	BPF_CORE_READ_INTO(&dport, sk, __sk_common.skc_dport);

	insert_flows(pid, sk, dport, FLOW_ACTIVE);

end:
	bpf_map_delete_elem(&tcp_connect_sockets, &tid);
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

// struct sock with udp_sendmsg may not miss ip addresses on listening socket.
// Addresses are retrieved from struct flowi4 with ip_make_skb.
// https://github.com/DataDog/datadog-agent/pull/6307
SEC("kprobe/ip_make_skb")
int BPF_KPROBE(ip_make_skb, struct sock *sk, struct flowi4 *flw4) {
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	__u32 pid = pid_tgid >> 32;
	__u16 dport, sport;
	struct ipv4_flow_key flow_key = {};

	BPF_CORE_READ_INTO(&sport, sk, __sk_common.skc_num);
	BPF_CORE_READ_INTO(&dport, sk, __sk_common.skc_dport);

	__u8 *sstate = bpf_map_lookup_elem(&udp_port_binding, &sport);
	if (sstate) {
		BPF_CORE_READ_INTO(&flow_key.saddr, flw4, daddr);
		BPF_CORE_READ_INTO(&flow_key.daddr, flw4, saddr);
		flow_key.direction = FLOW_PASSIVE;
		flow_key.lport = bpf_htons(sport);
	} else {
		BPF_CORE_READ_INTO(&flow_key.saddr, flw4, saddr);
		BPF_CORE_READ_INTO(&flow_key.daddr, flw4, daddr);
		flow_key.direction = FLOW_ACTIVE;
		flow_key.lport = dport;
	}
	flow_key.l4_proto = IPPROTO_UDP;

	insert_udp_flows(pid, &flow_key);

	log_debug("kprobe/udp_sendmsg: lport:%u, tgid:%u\n", sport, pid_tgid);
	return 0;
}

// struct sock with udp_recvmsg may not miss ip addresses on listening socket.
// Addresses are retrieved from arguments of skb_consume_udp.
SEC("kprobe/skb_consume_udp")
int BPF_KPROBE(skb_consume_udp, struct sock *sk, struct sk_buff *skb) {
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	__u32 pid = pid_tgid >> 32;

	struct udphdr *udphdr = (struct udphdr *)(BPF_CORE_READ(skb, head)
		+ BPF_CORE_READ(skb,transport_header));
	struct iphdr *iphdr = (struct iphdr *)(BPF_CORE_READ(skb, head) 
		+ BPF_CORE_READ(skb, network_header));

	struct ipv4_flow_key flow_key = {};
	__u16 sport = BPF_CORE_READ(udphdr, source);
	__u16 dport = BPF_CORE_READ(udphdr, dest);

	__u16 dport_key = bpf_htons(dport);
	__u8 *sstate = bpf_map_lookup_elem(&udp_port_binding, &dport_key);
	if (sstate) {
		flow_key.saddr = BPF_CORE_READ(iphdr, saddr);
		flow_key.daddr = BPF_CORE_READ(iphdr, daddr);
		flow_key.direction = FLOW_PASSIVE;
		flow_key.lport = dport;
	} else {
		flow_key.saddr = BPF_CORE_READ(iphdr, daddr);
		flow_key.daddr = BPF_CORE_READ(iphdr, saddr);
		flow_key.direction = FLOW_ACTIVE;
		flow_key.lport = sport;
	}

	flow_key.l4_proto = IPPROTO_UDP;

	insert_udp_flows(pid, &flow_key);

    log_debug("kprobe/skb_consume_udp: sport:%u, dport:%u, tid:%u\n",
		sport, dport, pid_tgid);
    return 0;
}

// for tracking UDP listening state
SEC("tracepoint/syscalls/sys_enter_socket")
int tracepoint__syscalls__sys_enter_socket(struct trace_event_raw_sys_enter* ctx) {
	__u64 tid = bpf_get_current_pid_tgid();
	int family = (int)ctx->args[0];
	int type = (int)ctx->args[1];

	log_debug("tp/sys_enter_socket: family=%u, type=%u, tid=%u\n", family, type, tid);

	// detect if protocol is udp or not.
    if ((family & (AF_INET | AF_INET6)) > 0 && (type & SOCK_DGRAM) > 0) {
		// pass
    } else {
		return 0;
	}

    __u8 ok = 1;
    bpf_map_update_elem(&entering_udp_sockets, &tid, &ok, BPF_ANY);

    log_debug("sys_enter_socket: found UDP family=%d, type=%d, tid=%u\n", family, type, tid);
	return 0;
}

// for tracking UDP listening state
SEC("tracepoint/syscalls/sys_exit_socket")
int tracepoint__syscalls__sys_exit_socket(struct trace_event_raw_sys_exit* ctx) {
    __u64 tid = bpf_get_current_pid_tgid();
    log_debug("tp/sys_exit_socket: fd=%d, tid=%u\n", ctx->ret, tid);

    __u8* is_udp = bpf_map_lookup_elem(&entering_udp_sockets, &tid);

    // socket(2) returns a file discriptor.
    __u64 fd_and_tid = (tid << 32) | ctx->ret;

    if (ctx->ret < 0) {
        log_debug("sys_exit_socket: socket() call failed, ret=%d, tid=%u\n", ctx->ret, tid);
		goto end;
	}

	if (!is_udp) {
        log_debug("sys_exit_socket: not UDP, fd=%d, tid=%u\n", ctx->ret, tid);
		goto end;
    }

    bpf_map_delete_elem(&entering_udp_sockets, &tid);

    __u64 ok = 1;
    bpf_map_update_elem(&unbound_udp_sockets, &fd_and_tid, &ok, BPF_ANY);

    log_debug("sys_exit_socket: found UDP fd=%d, tid=%u\n", ctx->ret, tid);
    return 0;

end:
    bpf_map_delete_elem(&entering_udp_sockets, &tid);
    bpf_map_delete_elem(&unbound_udp_sockets, &fd_and_tid);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_bind")
int tracepoint__syscalls__sys_enter_bind(struct trace_event_raw_sys_enter* ctx) {
    __u64 tid = bpf_get_current_pid_tgid();
	int fd = (int)ctx->args[0];
	const struct sockaddr *addr = (const struct sockaddr *)ctx->args[1];

    log_debug("tp/sys_enter_bind: fd=%u, addr=%x, tid=%u\n", fd, addr, tid);

	if (!addr) {
        return 0;
    }

    // determine if the fd for this process is an unbound UDP socket.
    __u64 fd_and_tid = (tid << 32) | fd;
    __u64* socket = bpf_map_lookup_elem(&unbound_udp_sockets, &fd_and_tid);
    if (!socket) {
        return 0;
    }

    __u16 sin_port = 0;
    sa_family_t family = 0;
    bpf_probe_read(&family, sizeof(sa_family_t), &addr->sa_family);
    if (family == AF_INET) {
        bpf_probe_read(&sin_port, sizeof(u16), &(((struct sockaddr_in*)addr)->sin_port));
    } else if (family == AF_INET6) {
        bpf_probe_read(&sin_port, sizeof(u16), &(((struct sockaddr_in6*)addr)->sin6_port));
    }

    sin_port = bpf_ntohs(sin_port);
    if (sin_port == 0) {
		log_debug("sys_enter_bind: sin_port == 0, family:%d, tid=%u\n", family, tid);
		return 0;
    }

	struct bind_args args = {};
	args.port = sin_port;
	args.fd = fd;
	bpf_map_update_elem(&entering_bind, &tid, &args, BPF_ANY);

	log_debug("sys_enter_bind: port=%d fd=%u tid=%u\n", sin_port, fd, tid);
	return 0;
}

SEC("tracepoint/syscalls/sys_exit_bind")
int tracepoint__syscalls__sys_exit_bind(struct trace_event_raw_sys_exit* ctx) {
    __u64 tid = bpf_get_current_pid_tgid();

    log_debug("tp/sys_exit_bind: ret=%d, tid=%u\n", ctx->ret, tid);

    if (ctx->ret != 0) {
        return 0;
    }

    struct bind_args* args = bpf_map_lookup_elem(&entering_bind, &tid);
    if (!args) {
        return 0;
    }

	struct port_binding_key key = {};
	key.port = args->port;
	__u8 state = PORT_LISTENING;
	bpf_map_update_elem(&udp_port_binding, &key, &state, BPF_ANY);

    log_debug("sys_exit_bind: UDP port:%u, tid:%u\n", args->port, tid);
    return 0;
}
