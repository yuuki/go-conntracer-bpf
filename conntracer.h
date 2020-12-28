#ifndef __CONNTRACER_H
#define __CONNTRACER_H

/* The maximum number of items in maps */
#define MAX_ENTRIES 8192
#define MAX_FLOW_ENTRIES 4096

#define TASK_COMM_LEN 16

struct ipv4_flow_key {
	__u32 saddr;
	__u32 daddr;
	__u16 dport;
};

struct ipv6_flow_key {
	__u8 saddr[16];
	__u8 daddr[16];
	__u16 dport;
};

struct event {
	union {
		__u32 saddr_v4;
		__u8 saddr_v6[16];
	};
	union {
		__u32 daddr_v4;
		__u8 daddr_v6[16];
	};
	char task[TASK_COMM_LEN];
	__u64 ts_us;
	int af; // AF_INET or AF_INET6
	__u32 pid;
	__u32 uid;
	__u16 dport;
};

struct flow {
    __u32 saddr_v4;  	// source address
    __u32 daddr_v4;  	// destination address
	char task[TASK_COMM_LEN];
	__u16 dport;  		// destination port
	__u8 direction; 	// 1: "connect"(active), 2: "accept"(passive)
};

struct flow_stat {
	__u32 uid;
	__u16 pid;
	__u16 connection_cnt;
	// __u16 latency_max;
	// __u16 latency_min;
	// __u16 latency_avg;
};

#endif /* __CONNTRACER_H */
