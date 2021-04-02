#ifndef __PORT_BINDING_H
#define __PORT_BINDING_H

#include "vmlinux.h"

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#include "conntracer.h"
#include "maps.h"

#define AF_INET		2
#define AF_INET6	10

static __always_inline void update_port_binding(__u16 lport) {
	struct port_binding_key key = {};
	key.port = lport;
	__u8 state = PORT_LISTENING;
	bpf_map_update_elem(&tcp_port_binding, &key, &state, BPF_ANY);
}

static __always_inline int sys_enter_socket(int family, int type, __u64 tid) {
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

static __always_inline int sys_exit_socket(int ret, __u64 tid) {
    __u8* is_udp = bpf_map_lookup_elem(&entering_udp_sockets, &tid);

    // socket(2) returns a file discriptor.
    __u64 fd_and_tid = (tid << 32) | ret;
    __u64 ok = 1;

    if (ret < 0) {
        log_debug("sys_exit_socket: socket() call failed, ret=%d, tid=%u\n", ret, tid);
		goto end;
	}

	if (!is_udp) {
        log_debug("sys_exit_socket: not UDP, fd=%d, tid=%u\n", ret, tid);
		goto end;
    }

    bpf_map_delete_elem(&entering_udp_sockets, &tid);

    bpf_map_update_elem(&unbound_udp_sockets, &fd_and_tid, &ok, BPF_ANY);

    log_debug("sys_exit_socket: found UDP fd=%d, tid=%u\n", ret, tid);
    return 0;

end:
    bpf_map_delete_elem(&entering_udp_sockets, &tid);
    bpf_map_delete_elem(&unbound_udp_sockets, &fd_and_tid);
	return 0;
}

static __always_inline int sys_enter_bind(int fd, const struct sockaddr *addr, __u64 tid) {
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
    bpf_probe_read_user(&family, sizeof(sa_family_t), &addr->sa_family);
    if (family == AF_INET) {
        bpf_probe_read_user(&sin_port, sizeof(u16), &(((struct sockaddr_in*)addr)->sin_port));
    } else if (family == AF_INET6) {
        bpf_probe_read_user(&sin_port, sizeof(u16), &(((struct sockaddr_in6*)addr)->sin6_port));
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

static __always_inline int sys_exit_bind(int ret, __u64 tid) {
    if (ret != 0) {
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

#endif
