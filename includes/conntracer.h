#ifndef __CONNTRACER_H
#define __CONNTRACER_H

/* The maximum number of items in maps */
#define MAX_ENTRIES 8192
#define MAX_FLOW_ENTRIES 4096

#define TASK_COMM_LEN 16

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
    __u32 saddr;  				// source address
    __u32 daddr;  				// destination address
	char task[TASK_COMM_LEN];
	__u16 lport;  				// listening port
	flow_direction direction; 	// 1: "connect"(active), 2: "accept"(passive)
	__u32 pid;
	struct flow_stat stat;
};

#endif /* __CONNTRACER_H */
