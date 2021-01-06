package conntracer

import (
	"fmt"
	"log"
	"net"
	"syscall"
	"time"
	"unsafe"

	// Put the C header files into Go module management
	_ "github.com/yuuki/gobpf-conntracer/includes"
	_ "github.com/yuuki/gobpf-conntracer/includes/bpf"
)

/*
#cgo CFLAGS: -Iincludes
#cgo LDFLAGS: -L. -l:libbpf.a -lelf -lz
#include <sys/resource.h>
#include <arpa/inet.h>
#include <errno.h>

#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "conntracer.skel.h"
#include "conntracer.h"

*/
import "C"

type Flow struct {
	SAddr       *net.IP
	DAddr       *net.IP
	ProcessName string
	DPort       uint16
	Direction   uint8 // 1: "connect"(active), 2: "accept"(passive)
	Stat        *FlowStat
}

type FlowStat struct {
	UID uint32
	PID uint32
}

type Tracer struct {
	obj *C.struct_conntracer_bpf
}

// NewTracer creates a Tracer object.
func NewTracer(cb func([]*Flow) error, interval time.Duration) (*Tracer, error) {
	// Bump RLIMIT_MEMLOCK to allow BPF sub-system to do anything
	if err := bumpMemlockRlimit(); err != nil {
		return nil, err
	}

	obj := C.conntracer_bpf__open_and_load()
	if obj == nil {
		return nil, fmt.Errorf("failed to open and load BPF object\n")
	}
	defer C.free(unsafe.Pointer(obj))

	cerr := C.conntracer_bpf__attach(obj)
	if cerr != 0 {
		return nil, fmt.Errorf("failed to attach BPF programs: %v", C.strerror(-cerr))
	}

	go pollFlows(interval, cb, C.bpf_map__fd(obj.maps.flows))

	return &Tracer{obj: obj}, nil
}

func pollFlows(interval time.Duration, cb func([]*Flow) error, fd C.int) {
	t := time.NewTicker(interval)
	defer t.Stop()

	for {
		select {
		case <-t.C:
			flows, err := dumpFlows(fd)
			if err != nil {
				log.Println(err)
			}
			if err := cb(flows); err != nil {
				log.Println(err)
			}
		}
	}
}

func dumpFlows(fd C.int) ([]*Flow, error) {
	pKey, pNextKey := C.NULL, unsafe.Pointer(&C.struct_ipv4_flow_key{})
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
		batchSize, n C.uint = 10, 0
		nRead        int    = 0
		ret          C.int  = 0
		err          error
	)
	for ret == 0 {
		n = batchSize
		// TODO: ckeys, cvalues pointer increment
		ret, err = C.bpf_map_lookup_and_delete_batch(fd, pKey, pNextKey, ckeys, cvalues, &n, opts)
		if ret != 0 && err != syscall.Errno(syscall.ENOENT) {
			return nil, fmt.Errorf("Error bpf_map_lookup_and_delete_batch, fd:%d, ret:%d, %s", fd, ret, err)
		}
		nRead += (int)(n)
		pKey = pNextKey // TODO: test
	}

	flows := make([]*Flow, 0, nRead)
	for i := 0; i < nRead; i++ {
		saddr := inetNtop((uint32)(values[i].saddr))
		daddr := inetNtop((uint32)(values[i].daddr))
		flow := &Flow{
			SAddr:       &saddr,
			DAddr:       &daddr,
			ProcessName: C.GoString((*C.char)(unsafe.Pointer(&values[i].task))),
			DPort:       ntohs((uint16)(values[i].dport)),
			Direction:   uint8(values[i].direction),
			Stat: &FlowStat{
				UID: (uint32)(values[i].stat.uid),
				PID: (uint32)(values[i].stat.pid),
			},
		}
		flows = append(flows, flow)
	}

	return flows, nil
}
