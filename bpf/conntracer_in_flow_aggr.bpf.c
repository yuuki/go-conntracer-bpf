// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
// Copyright (c) 2020 Yuuki Tsubouchi

#include "vmlinux.h"

#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include "conntracer.h"
#include "conntracer_bpf_read.h"
#include "port_binding.h"

#define AF_INET 2
#define AF_INET6 10

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct flow_tuple);
    __type(value, struct single_flow);
    __uint(max_entries, MAX_SINGLE_FLOW_ENTRIES);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} flows SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct flow_tuple);
    __type(value, struct single_flow_stat);
    __uint(max_entries, MAX_SINGLE_FLOW_ENTRIES);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} flow_stats SEC(".maps");

static __always_inline void insert_tcp_flows(struct flow_tuple* tuple,
                                             __u8 direction) {
    struct single_flow flow = {}, *val;

    flow.sport = tuple->sport;
    flow.dport = tuple->dport;
    switch (direction) {
        case FLOW_ACTIVE:
            flow.lport = tuple->dport;
            break;
        case FLOW_PASSIVE:
            flow.lport = tuple->sport;
            break;
        default:
            log_debug("unknown direction:%d pid:%u\n", direction, tuple->pid);
            return;
    }
    flow.pid = tuple->pid;
    flow.direction = direction;
    bpf_get_current_comm(flow.task, sizeof(flow.task));

    flow.saddr = tuple->saddr;
    flow.daddr = tuple->daddr;
    tuple->l4_proto = IPPROTO_TCP;
    flow.l4_proto = tuple->l4_proto;

    val = bpf_map_lookup_elem(&flows, tuple);
    if (val) {
        return;
    }
    bpf_map_update_elem(&flows, tuple, &flow, BPF_ANY);
}

static __always_inline void update_message(struct flow_tuple* tuple,
                                           size_t sent_bytes,
                                           size_t recv_bytes) {
    struct single_flow_stat empty = {};
    __builtin_memset(&empty, 0, sizeof(struct single_flow_stat));
    bpf_map_update_elem(&flow_stats, tuple, &empty, BPF_NOEXIST);

    struct single_flow_stat* val;
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

static __always_inline void insert_udp_flows(struct flow_tuple* tuple,
                                             __u8 direction, __u16 lport) {
    struct single_flow flow = {};

    flow.saddr = tuple->saddr;
    flow.daddr = tuple->daddr;
    flow.sport = tuple->sport;
    flow.dport = tuple->dport;
    flow.lport = lport;
    flow.direction = direction;
    flow.l4_proto = tuple->l4_proto;
    flow.pid = tuple->pid;
    flow.l4_proto = IPPROTO_UDP;
    bpf_get_current_comm(flow.task, sizeof(flow.task));

    bpf_map_update_elem(&flows, tuple, &flow, BPF_ANY);
}

SEC("kprobe/tcp_v4_connect")
int BPF_KPROBE(tcp_v4_connect, struct sock* sk) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;
    __u32 tid = pid_tgid;

    bpf_map_update_elem(&tcp_connect_sockets, &tid, &sk, BPF_ANY);

    log_debug("kprobe/tcp_v4_connect: pid_tgid:%u\n", pid_tgid);
    return 0;
}

SEC("kretprobe/tcp_v4_connect")
int BPF_KRETPROBE(tcp_v4_connect_ret, int ret) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;
    __u32 tid = pid_tgid;

    struct sock** skpp = bpf_map_lookup_elem(&tcp_connect_sockets, &tid);
    if (!skpp) return 0;

    if (ret) goto end;

    struct flow_tuple tuple = {};
    read_flow_tuple_for_tcp(&tuple, *skpp, pid);
    insert_tcp_flows(&tuple, FLOW_ACTIVE);
    update_message(&tuple, 0, 0);

    log_debug("kretprobe/tcp_v4_connect: tgid:%u\n", pid_tgid);
end:
    bpf_map_delete_elem(&tcp_connect_sockets, &pid_tgid);
    return 0;
}

SEC("kretprobe/inet_csk_accept")
int BPF_KRETPROBE(inet_csk_accept_ret, struct sock* sk) {
    __u64 tgid = bpf_get_current_pid_tgid();
    __u32 pid = tgid >> 32;
    __u16 lport = 0;

    if (!sk) {
        return 0;
    }

    struct flow_tuple tuple = {};
    read_flow_tuple_for_tcp(&tuple, sk, pid);
    insert_tcp_flows(&tuple, FLOW_PASSIVE);
    update_message(&tuple, 0, 0);

    log_debug("kretprobe/inet_csk_accept: lport:%u, pid_tgid:%u\n", lport,
              tgid);
    return 0;
}

SEC("kprobe/tcp_sendmsg")
int BPF_KPROBE(tcp_sendmsg, struct sock* sk, struct msghdr* msg, size_t size) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;
    log_debug("kprobe/tcp_sendmsg: pid_tgid:%d, size:%d\n", pid_tgid, size);

    struct flow_tuple tuple = {};
    read_flow_tuple_for_tcp(&tuple, sk, pid);
    update_message(&tuple, size, 0);

    return 0;
}

SEC("kprobe/tcp_cleanup_rbuf")
int BPF_KPROBE(tcp_cleanup_rbuf, struct sock* sk, int copied) {
    if (copied < 0) {
        return 0;
    }
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;
    log_debug("kprobe/tcp_cleanup_rbuf: pid_tgid:%d, copied:%d\n", pid_tgid,
              copied);

    struct flow_tuple tuple = {};
    read_flow_tuple_for_tcp(&tuple, sk, pid);
    update_message(&tuple, 0, copied);

    return 0;
}

// struct sock with udp_sendmsg may not miss ip addresses on listening socket.
// Addresses are retrieved from struct flowi4 with ip_make_skb.
// https://github.com/DataDog/datadog-agent/pull/6307
SEC("kprobe/ip_send_skb")
int BPF_KPROBE(ip_send_skb, struct net* net, struct sk_buff* skb) {
    __u16 protocol = BPF_CORE_READ(skb, protocol);
    if (protocol != IPPROTO_UDP) {
        return 0;
    }

    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;
    struct flow_tuple tuple = {};
    __u8 direction;
    __u16 lport;
    size_t msglen = 0;

    BPF_CORE_READ_INTO(&msglen, get_udphdr(skb), len);
    msglen = msglen - sizeof(struct udphdr);

    read_flow_tuple_for_udp_send(&tuple, &direction, &lport, skb);
    tuple.pid = pid;
    insert_udp_flows(&tuple, direction, lport);
    update_message(&tuple, msglen, 0);

    log_debug("kprobe/ip_make_skb: sport:%u, dport:%u, tgid:%u\n", tuple.sport,
              tuple.dport, pid_tgid);
    return 0;
}

// struct sock with udp_recvmsg may not miss ip addresses on listening socket.
// Addresses are retrieved from arguments of skb_consume_udp.
SEC("kprobe/skb_consume_udp")
int BPF_KPROBE(skb_consume_udp, struct sock* sk, struct sk_buff* skb, int len) {
    __u64 tgid = bpf_get_current_pid_tgid();
    __u32 pid = tgid >> 32;
    struct flow_tuple tuple = {};
    __u8 direction;
    __u16 lport;

    if (len < 0) {
        return 0;
    }

    read_flow_tuple_for_udp_recv(&tuple, &direction, &lport, sk, skb);
    tuple.pid = pid;
    insert_udp_flows(&tuple, direction, lport);
    update_message(&tuple, 0, len);

    log_debug("kprobe/skb_consume_udp: sport:%u, dport:%u, tid:%u\n",
              tuple.sport, tuple.dport, tgid);
    return 0;
}

// for tracking UDP listening state
SEC("tracepoint/syscalls/sys_enter_socket")
int tracepoint__syscalls__sys_enter_socket(
    struct trace_event_raw_sys_enter* ctx) {
    __u64 tid = bpf_get_current_pid_tgid();
    int family = (int)ctx->args[0];
    int type = (int)ctx->args[1];
    log_debug("tp/sys_enter_socket: family=%u, type=%u, tid=%u\n", family, type,
              tid);

    return sys_enter_socket(family, type, tid);
}

// for tracking UDP listening state
SEC("tracepoint/syscalls/sys_exit_socket")
int tracepoint__syscalls__sys_exit_socket(
    struct trace_event_raw_sys_exit* ctx) {
    __u64 tid = bpf_get_current_pid_tgid();
    log_debug("tp/sys_exit_socket: fd=%d, tid=%u\n", ctx->ret, tid);

    return sys_exit_socket(ctx->ret, tid);
}

SEC("tracepoint/syscalls/sys_enter_bind")
int tracepoint__syscalls__sys_enter_bind(
    struct trace_event_raw_sys_enter* ctx) {
    __u64 tid = bpf_get_current_pid_tgid();
    int fd = (int)ctx->args[0];
    const struct sockaddr* addr = (const struct sockaddr*)ctx->args[1];

    log_debug("tp/sys_enter_bind: fd=%u, addr=%x, tid=%u\n", fd, addr, tid);
    return sys_enter_bind(fd, addr, tid);
}

SEC("tracepoint/syscalls/sys_exit_bind")
int tracepoint__syscalls__sys_exit_bind(struct trace_event_raw_sys_exit* ctx) {
    __u64 tid = bpf_get_current_pid_tgid();

    log_debug("tp/sys_exit_bind: ret=%d, tid=%u\n", ctx->ret, tid);
    return sys_exit_bind(ctx->ret, tid);
}
