package main

import (
	"encoding/binary"
	"fmt"
	"log"
	"math"
	"net"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

/*
#cgo CFLAGS: -I ../../ -I../../includes
#cgo LDFLAGS: -L../../ -l:libbpf.a -lelf -lz -Wl,-rpath=../../
#include <sys/resource.h>
#include <arpa/inet.h>
#include <errno.h>

#include <bpf/libbpf.h>
#include <bpf/bpf.h>
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

type flow struct {
	SAddr       *net.IP
	DAddr       *net.IP
	ProcessName string
	DPort       uint16
	Direction   uint8 // 1: "connect"(active), 2: "accept"(passive)
	Stat        *flowStat
}

type flowStat struct {
	UID uint32
	PID uint32
}

func ntohs(i uint16) uint16 {
	return binary.BigEndian.Uint16((*(*[2]byte)(unsafe.Pointer(&i)))[:])
}

func inetNtop(i uint16) net.IP {
	return net.IP((*(*[net.IPv4len]byte)(unsafe.Pointer(&i)))[:])
}

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

func pollFlows(interval time.Duration, fd C.int) {
	t := time.NewTicker(interval)
	defer t.Stop()

	for {
		select {
		case <-t.C:
			flows, err := scanFlows(fd)
			if err != nil {
				log.Println(err)
			}
			for _, flow := range flows {
				fmt.Printf("%+v\n", flow)
			}
		}
	}
}

func scanFlows(fd C.int) ([]*flow, error) {
	// LIBBPF_API int bpf_map_lookup_and_delete_batch(int fd, void *in_batch,
	// 			void *out_batch, void *keys,
	// 			void *values, __u32 *count,
	// 			const struct bpf_map_batch_opts *opts);
	pKey := C.NULL
	pNextKey := unsafe.Pointer(&C.struct_ipv4_flow_key{})
	keys := make([]C.struct_ipv4_flow_key, C.MAX_ENTRIES)
	ckeys := unsafe.Pointer(&keys[0])
	values := make([]C.struct_flow, C.MAX_ENTRIES)
	cvalues := unsafe.Pointer(&values[0])
	opts := &C.struct_bpf_map_batch_opts{
		elem_flags: 0,
		flags:      0,
		sz:         C.sizeof_struct_bpf_map_batch_opts,
	}

	var (
		batchSize C.uint = 10
		n         C.uint = 0
		nRead     int    = 0
		ret       C.int  = 0
		cerr      error
	)
	for ret == 0 {
		n = batchSize
		// TODO: ckeys, cvalues pointer increment
		ret, cerr = C.bpf_map_lookup_and_delete_batch(fd, pKey, pNextKey, ckeys, cvalues, &n, opts)
		if ret != 0 && cerr != syscall.Errno(syscall.ENOENT) {
			return nil, fmt.Errorf("Error bpf_map_lookup_and_delete_batch: fd:%d, %d, %+v, %v", fd, ret, cerr)
		}
		nRead += (int)(n)
		pKey = pNextKey // TODO: test
	}

	fmt.Printf("nRead: %d\n", nRead)
	fmt.Printf("%+v, %+v\n", keys[0], values[0])

	flows := make([]*flow, 0, nRead)
	for i := 0; i < nRead; i++ {
		saddr := inetNtop((uint16)(values[i].saddr))
		daddr := inetNtop((uint16)(values[i].daddr))
		flow := &flow{
			SAddr:       &saddr,
			DAddr:       &daddr,
			ProcessName: C.GoString((*C.char)(unsafe.Pointer(&values[i].task))),
			DPort:       ntohs((uint16)(values[i].dport)),
			Direction:   uint8(values[i].direction),
			Stat: &flowStat{
				UID: (uint32)(values[i].stat.uid),
				PID: (uint32)(values[i].stat.pid),
			},
		}
		flows = append(flows, flow)
	}

	return flows, nil
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

	go pollFlows(3*time.Second, C.bpf_map__fd(obj.maps.flows))
	printEvents(C.bpf_map__fd(obj.maps.events))
}
