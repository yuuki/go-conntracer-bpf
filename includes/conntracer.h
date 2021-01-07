#ifndef __CONNTRACER_H
#define __CONNTRACER_H

/* The maximum number of items in maps */
#define MAX_ENTRIES 8192
#define MAX_FLOW_ENTRIES 4096

#define TASK_COMM_LEN 16

enum flow_direction
{
	FLOW_ACTIVE,
	FLOW_PASSIVE
};

struct ipv4_flow_key {
	__u32 saddr;
	__u32 daddr;
	__u16 dport;
	__u8 direction; 	// 1: "connect"(active), 2: "accept"(passive)
};

struct ipv6_flow_key {
	__u8 saddr[16];
	__u8 daddr[16];
	__u16 dport;
};

struct flow_stat {
	__u32 uid;
	__u32 pid;
	__u16 connection_cnt;
	// __u16 latency_max;
	// __u16 latency_min;
	// __u16 latency_avg;
};

struct flow {
    __u32 saddr;  		// source address
    __u32 daddr;  		// destination address
	char task[TASK_COMM_LEN];
	__u16 dport;  		// destination port
	__u8 direction; 	// 1: "connect"(active), 2: "accept"(passive)
	struct flow_stat stat;
};

#endif /* __CONNTRACER_H */
