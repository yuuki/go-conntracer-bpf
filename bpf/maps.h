#ifndef __MAPS_H
#define __MAPS_H

#include "vmlinux.h"

#include <bpf/bpf_helpers.h>

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, u32);
	__type(value, struct sock *);
	__uint(map_flags, BPF_F_NO_PREALLOC);
} tcp_connect_sockets SEC(".maps");

/* tcp_port_binding is a map for tracing listening TCP ports. 
Entries are added to the map in the context of the inet_csk_accept syscall. 
 */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_PORT_BINDING_ENTRIES);
	__type(key, struct port_binding_key);
	__type(value, __u8);		// protocol state
} tcp_port_binding SEC(".maps");

/* udp_port_binding is a map for tracking UDP LISNING or CLOSED ports.
udp_port_binding enables to register entire local ports and insert or update the port number and state at the timing when the port state changes.
*/
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


#endif
