package main

import (
	"fmt"
	"math"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

/*
#cgo CFLAGS: -I ../../
#cgo LDFLAGS: -L../../ -l:libbpf.a -lelf -lz -Wl,-rpath=../../
#include <sys/resource.h>
#include <arpa/inet.h>
#include <errno.h>

#include <bpf/libbpf.h>
#include "conntracer.skel.h"
#include "conntracer.h"

static void handle_event(void *ctx, int cpu, void *data, __u32 data_sz)
{
	const struct event *event = data;
	char src[INET6_ADDRSTRLEN];
	char dst[INET6_ADDRSTRLEN];
	union {
		struct in_addr  x4;
		struct in6_addr x6;
	} s, d;
	static __u64 start_ts;

	if (event->af == AF_INET) {
		s.x4.s_addr = event->saddr_v4;
		d.x4.s_addr = event->daddr_v4;
	} else {
		warn("broken event: event->af=%d", event->af);
		return;
	}

	printf("%-6d %-12.12s %-2d %-16s %-16s %-4d\n",
	       event->pid, event->task,
	       event->af == AF_INET ? 4 : 6,
	       inet_ntop(event->af, &s, src, sizeof(src)),
	       inet_ntop(event->af, &d, dst, sizeof(dst)),
	       ntohs(event->dport));
}

static void handle_lost_events(void *ctx, int cpu, __u64 lost_cnt)
{
	warn("Lost %llu events on CPU #%d!\n", lost_cnt, cpu);
}

struct perf_buffer_opts pb_opts = {
	.sample_cb = handle_event,
	.lost_cb = handle_lost_events,
};
struct perf_buffer *pb = NULL;
int err;

*/
import "C"

func bumpMemlockRlimit() error {
	rl := unix.Rlimit{
		Cur: math.MaxUint64,
		Max: math.MaxUint64,
	}
	err := unix.Setrlimit(unix.RLIMIT_MEMLOCK, &rl)
	if err != nil {
		return err
	}
	return nil
}

func printEvents(perf_map_fd C.int) {
	pb := C.perf_buffer__new(perf_map_fd, 128, &C.pb_opts)
	defer C.perf_buffer__free(pb)

	cerr := C.libbpf_get_error(unsafe.Pointer(pb))
	if cerr != 0 {
		pb = nil
		fmt.Printf("failed to open perf buffer: %d\n", cerr)
		return
	}

	for {
		cerr, err := C.perf_buffer__poll(pb, 100)
		if cerr < 0 && err != syscall.Errno(syscall.EINTR) {
			fmt.Printf("Error polling perf buffer: %d\n", cerr)
			return
		}
	}
}

func main() {
	/* Bump RLIMIT_MEMLOCK to allow BPF sub-system to do anything */
	if err := bumpMemlockRlimit(); err != nil {
		panic(err)
	}

	obj := C.conntracer_bpf__open_and_load()
	if obj == nil {
		panic("failed to open and load BPF object\n")
	}
	defer C.free(unsafe.Pointer(obj))

	cerr := C.conntracer_bpf__attach(obj)
	if cerr != 0 {
		panic(fmt.Sprintf("failed to attach BPF programs: %s\n", C.strerror(-cerr)))
	}

	printEvents(C.bpf_map__fd(obj.maps.events))
}
