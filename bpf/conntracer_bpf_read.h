#ifndef __CONNTRACER_BPF_READ_H
#define __CONNTRACER_BPF_READ_H

#include "vmlinux.h"

#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>

#include "conntracer.h"
#include "maps.h"

static __always_inline
void read_flow_tuple_for_tcp(struct flow_tuple *tuple, struct sock *sk, pid_t pid) {
	BPF_CORE_READ_INTO(&tuple->saddr, sk, __sk_common.skc_rcv_saddr);
	BPF_CORE_READ_INTO(&tuple->daddr, sk, __sk_common.skc_daddr);
	BPF_CORE_READ_INTO(&tuple->sport, sk, __sk_common.skc_num);
	BPF_CORE_READ_INTO(&tuple->dport, sk, __sk_common.skc_dport);
	tuple->pid = pid;
	tuple->l4_proto = IPPROTO_TCP;
}

static __always_inline
void read_aggr_flow_tuple_for_tcp(struct aggregated_flow_tuple *tuple, struct sock *sk, flow_direction direction) {
	__u16 sport, dport;

	BPF_CORE_READ_INTO(&tuple->saddr, sk, __sk_common.skc_rcv_saddr);
	BPF_CORE_READ_INTO(&tuple->daddr, sk, __sk_common.skc_daddr);
	BPF_CORE_READ_INTO(&sport, sk, __sk_common.skc_num);
	BPF_CORE_READ_INTO(&dport, sk, __sk_common.skc_dport);

	tuple->l4_proto = IPPROTO_TCP;

	struct port_binding_key pb = {};
	switch (direction) {
		case FLOW_ACTIVE:
			tuple->lport = dport;
			break;
		case FLOW_PASSIVE:
			tuple->lport = sport;
			break;
		case FLOW_UNKNOWN:
			pb.port = sport;
			__u8 *ok = bpf_map_lookup_elem(&tcp_port_binding, &pb);
			direction = ok ? FLOW_PASSIVE : FLOW_ACTIVE;
			tuple->lport = ok ? sport : dport;
			break;
		default:
			log_debug("unreachable statement\n");
			break;
	}
	tuple->direction = direction;
}

static __always_inline void read_flow_for_udp_send(struct aggregated_flow_tuple *tuple, struct sock *sk, struct flowi4 *flw4) {
	__u16 dport, sport;

	BPF_CORE_READ_INTO(&sport, sk, __sk_common.skc_num);
	BPF_CORE_READ_INTO(&dport, sk, __sk_common.skc_dport);

	__u8 *sstate = bpf_map_lookup_elem(&udp_port_binding, &sport);
	if (sstate) {
		BPF_CORE_READ_INTO(&tuple->saddr, flw4, daddr);
		BPF_CORE_READ_INTO(&tuple->daddr, flw4, saddr);
		tuple->direction = FLOW_PASSIVE;
		tuple->lport = bpf_htons(sport);
	} else {
		BPF_CORE_READ_INTO(&tuple->saddr, flw4, saddr);
		BPF_CORE_READ_INTO(&tuple->daddr, flw4, daddr);
		tuple->direction = FLOW_ACTIVE;
		tuple->lport = dport;
	}
	tuple->l4_proto = IPPROTO_UDP;
}

static __always_inline void read_flow_for_udp_recv(struct aggregated_flow_tuple *tuple, struct sock *sk, struct sk_buff *skb) {
	struct udphdr *udphdr = (struct udphdr *)(BPF_CORE_READ(skb, head)
		+ BPF_CORE_READ(skb,transport_header));
	struct iphdr *iphdr = (struct iphdr *)(BPF_CORE_READ(skb, head)
        + BPF_CORE_READ(skb, network_header));

	__u16 sport = BPF_CORE_READ(udphdr, source);
	__u16 dport = BPF_CORE_READ(udphdr, dest);

	__u16 dport_key = bpf_htons(dport);
	__u8 *sstate = bpf_map_lookup_elem(&udp_port_binding, &dport_key);
	if (sstate) {
		tuple->saddr = BPF_CORE_READ(iphdr, saddr);
		tuple->daddr = BPF_CORE_READ(iphdr, daddr);
		tuple->direction = FLOW_PASSIVE;
		tuple->lport = dport;
	} else {
		tuple->saddr = BPF_CORE_READ(iphdr, daddr);
		tuple->daddr = BPF_CORE_READ(iphdr, saddr);
		tuple->direction = FLOW_ACTIVE;
		tuple->lport = sport;
	}

	tuple->l4_proto = IPPROTO_UDP;
}

static __always_inline 
void read_flow_tuple_for_udp_send(struct flow_tuple *tuple, 
	__u8 *direction, __u16 *lport, struct sock *sk, struct flowi4 *flw4)
{
	__u16 dport, sport;

	BPF_CORE_READ_INTO(&sport, sk, __sk_common.skc_num);
	BPF_CORE_READ_INTO(&dport, sk, __sk_common.skc_dport);

	__u8 *sstate = bpf_map_lookup_elem(&udp_port_binding, &sport);
	if (sstate) {
		BPF_CORE_READ_INTO(&tuple->saddr, flw4, daddr);
		BPF_CORE_READ_INTO(&tuple->daddr, flw4, saddr);
		*direction = FLOW_PASSIVE;
		*lport = bpf_htons(sport);
	} else {
		BPF_CORE_READ_INTO(&tuple->saddr, flw4, saddr);
		BPF_CORE_READ_INTO(&tuple->daddr, flw4, daddr);
		*direction = FLOW_ACTIVE;
		*lport = dport;
	}
	tuple->l4_proto = IPPROTO_UDP;
}

static __always_inline
void read_flow_tuple_for_udp_recv(struct flow_tuple *tuple, 
	__u8 *direction, __u16 *lport, struct sock *sk, struct sk_buff *skb)
{
	struct udphdr *udphdr = (struct udphdr *)(BPF_CORE_READ(skb, head)
		+ BPF_CORE_READ(skb,transport_header));
	struct iphdr *iphdr = (struct iphdr *)(BPF_CORE_READ(skb, head)
        + BPF_CORE_READ(skb, network_header));

	__u16 sport = BPF_CORE_READ(udphdr, source);
	__u16 dport = BPF_CORE_READ(udphdr, dest);

	__u16 dport_key = bpf_htons(dport);
	__u8 *sstate = bpf_map_lookup_elem(&udp_port_binding, &dport_key);
	if (sstate) {
		tuple->saddr = BPF_CORE_READ(iphdr, saddr);
		tuple->daddr = BPF_CORE_READ(iphdr, daddr);
		*direction = FLOW_PASSIVE;
		*lport = dport;
	} else {
		tuple->saddr = BPF_CORE_READ(iphdr, daddr);
		tuple->daddr = BPF_CORE_READ(iphdr, saddr);
		*direction = FLOW_ACTIVE;
		*lport = sport;
	}

	tuple->l4_proto = IPPROTO_UDP;
}

#endif
