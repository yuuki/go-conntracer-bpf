#ifndef __CONNTRACER_H
#define __CONNTRACER_H

/* The maximum number of items in maps */
#define MAX_ENTRIES 8192

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

#endif /* __CONNTRACER_H */
