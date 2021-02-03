#ifndef __CONNTRACER_H
#define __CONNTRACER_H

/* The maximum number of items in maps */
#define MAX_ENTRIES 8192
#define MAX_FLOW_ENTRIES 4096
#define MAX_PORT_BINDING_ENTRIES 65535

#define TASK_COMM_LEN 16

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

typedef enum
{
	FLOW_UNKNOWN = 1,
	FLOW_ACTIVE, // 'active open'.
	FLOW_PASSIVE // 'passive open'
} flow_direction;

struct ipv4_flow_key {
	__u32 saddr;
	__u32 daddr;
	__u16 lport;				// listening port
	flow_direction direction; 	// 0x10: "connect"(active), 0x20: "accept"(passive)
	__u8 l4_proto;           	// sk_protocol such as IPPRPTO_TCP, IPPROTO_UDP
};

struct ipv6_flow_key {
	__u8 saddr[16];
	__u8 daddr[16];
	__u16 dport;
};

struct flow_stat {
	__u32 connections;  	// the number of connections
	// __u16 latency_max;
	// __u16 latency_min;
	// __u16 latency_avg;
};

struct flow {
	__u64 ts_us;
    __u32 saddr;  				// source address
    __u32 daddr;  				// destination address
	char task[TASK_COMM_LEN];
	__u16 lport;  				// listening port
	flow_direction direction; 	// 1: "connect"(active), 2: "accept"(passive)
	__u32 pid;
	__u8 l4_proto;
	struct flow_stat stat;
};

struct bind_args {
    __u16 port;
    __u64 fd;
};

enum {
	PORT_CLOSED = 0,
	PORT_LISTENING = 1,
};

struct port_binding_key {
 	__u16 port;
};

#endif /* __CONNTRACER_H */
