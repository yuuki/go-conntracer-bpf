#ifndef __CONNTRACER_BPF_READ_H
#define __CONNTRACER_BPF_READ_H

#include "vmlinux.h"

#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>

#include "conntracer.h"
#include "maps.h"

static __always_inline void read_flow_for_udp_send(struct ipv4_flow_key *flow_key, struct sock *sk, struct flowi4 *flw4) {
	__u16 dport, sport;

	BPF_CORE_READ_INTO(&sport, sk, __sk_common.skc_num);
	BPF_CORE_READ_INTO(&dport, sk, __sk_common.skc_dport);

	__u8 *sstate = bpf_map_lookup_elem(&udp_port_binding, &sport);
	if (sstate) {
		BPF_CORE_READ_INTO(&flow_key->saddr, flw4, daddr);
		BPF_CORE_READ_INTO(&flow_key->daddr, flw4, saddr);
		flow_key->direction = FLOW_PASSIVE;
		flow_key->lport = bpf_htons(sport);
	} else {
		BPF_CORE_READ_INTO(&flow_key->saddr, flw4, saddr);
		BPF_CORE_READ_INTO(&flow_key->daddr, flw4, daddr);
		flow_key->direction = FLOW_ACTIVE;
		flow_key->lport = dport;
	}
	flow_key->l4_proto = IPPROTO_UDP;
}

static __always_inline void read_flow_for_udp_recv(struct ipv4_flow_key *flow_key, struct sock *sk, struct sk_buff *skb) {
	struct udphdr *udphdr = (struct udphdr *)(BPF_CORE_READ(skb, head)
		+ BPF_CORE_READ(skb,transport_header));
	struct iphdr *iphdr = (struct iphdr *)(BPF_CORE_READ(skb, head)
        + BPF_CORE_READ(skb, network_header));

	__u16 sport = BPF_CORE_READ(udphdr, source);
	__u16 dport = BPF_CORE_READ(udphdr, dest);

	__u16 dport_key = bpf_htons(dport);
	__u8 *sstate = bpf_map_lookup_elem(&udp_port_binding, &dport_key);
	if (sstate) {
		flow_key->saddr = BPF_CORE_READ(iphdr, saddr);
		flow_key->daddr = BPF_CORE_READ(iphdr, daddr);
		flow_key->direction = FLOW_PASSIVE;
		flow_key->lport = dport;
	} else {
		flow_key->saddr = BPF_CORE_READ(iphdr, daddr);
		flow_key->daddr = BPF_CORE_READ(iphdr, saddr);
		flow_key->direction = FLOW_ACTIVE;
		flow_key->lport = sport;
	}

	flow_key->l4_proto = IPPROTO_UDP;
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
