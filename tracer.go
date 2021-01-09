// +build linux

package conntracer

import (
	"errors"
	"fmt"
	"log"
	"net"
	"syscall"
	"time"
	"unsafe"

	// Put the C header files into Go module management
	_ "github.com/yuuki/go-conntracer-bpf/includes"
	_ "github.com/yuuki/go-conntracer-bpf/includes/bpf"
)

/*
#include <sys/resource.h>
#include <arpa/inet.h>
#include <errno.h>

#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "conntracer.skel.h"
#include "conntracer.h"

*/
import "C"

// FlowDirection are bitmask that represents both Active or Passive.
type FlowDirection uint8

const (
	// FlowUnknown are unknown flow.
	FlowUnknown FlowDirection = 1 << iota
	// FlowActive are 'active open'.
	FlowActive
	// FlowPassive are 'passive open'
	FlowPassive

	// defaultFlowMapOpsBatchSize is batch size of BPF map(flows) lookup_and_delete.
	defaultFlowMapOpsBatchSize = 10
)

// Flow is a bunch of aggregated connections group by listening port.
type Flow struct {
	SAddr       *net.IP
	DAddr       *net.IP
	ProcessName string
	LPort       uint16 // Listening port
	Direction   FlowDirection
	LastPID     uint32
	Stat        *FlowStat
}

// FlowStat is an statistics for Flow.
type FlowStat struct {
	NewConnections uint32
}

// Tracer is an object for state retention.
type Tracer struct {
	obj      *C.struct_conntracer_bpf
	cb       func([]*Flow) error
	stopChan chan struct{}

	// option
	batchSize int
}

// NewTracer creates a Tracer object.
func NewTracer(cb func([]*Flow) error) (*Tracer, error) {
	// Bump RLIMIT_MEMLOCK to allow BPF sub-system to do anything
	if err := bumpMemlockRlimit(); err != nil {
		return nil, err
	}

	obj := C.conntracer_bpf__open_and_load()
	if obj == nil {
		return nil, errors.New("failed to open and load BPF object")
	}

	cerr := C.conntracer_bpf__attach(obj)
	if cerr != 0 {
		return nil, fmt.Errorf("failed to attach BPF programs: %v", C.strerror(-cerr))
	}

	stopChan := make(chan struct{})

	t := &Tracer{
		obj:       obj,
		cb:        cb,
		stopChan:  stopChan,
		batchSize: defaultFlowMapOpsBatchSize,
	}
	return t, nil
}

// Close closes tracer.
func (t *Tracer) Close() {
	close(t.stopChan)
	C.conntracer_bpf__destroy(t.obj)
}

// Start starts polling loop.
func (t *Tracer) Start(interval time.Duration) {
	go t.pollFlows(interval)
}

// Stop stops polling loop.
func (t *Tracer) Stop() {
	t.stopChan <- struct{}{}
}

func (t *Tracer) flowsMapFD() C.int {
	return C.bpf_map__fd(t.obj.maps.flows)
}

func (t *Tracer) pollFlows(interval time.Duration) {
	tick := time.NewTicker(interval)
	defer tick.Stop()

	for {
		select {
		case <-t.stopChan:
			return
		case <-tick.C:
			flows, err := dumpFlows(t.flowsMapFD())
			if err != nil {
				log.Println(err)
			}
			if err := t.cb(flows); err != nil {
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
		ret, err = C.bpf_map_lookup_and_delete_batch(fd, pKey, pNextKey,
			unsafe.Pointer(uintptr(ckeys)+uintptr(nRead*C.sizeof_struct_ipv4_flow_key)),
			unsafe.Pointer(uintptr(cvalues)+uintptr(nRead*C.sizeof_struct_ipv4_flow_key)),
			&n, opts)
		if err != nil && err != syscall.Errno(syscall.ENOENT) {
			return nil, fmt.Errorf("Error bpf_map_lookup_and_delete_batch, fd:%d, ret:%d, %s", fd, ret, err)
		}
		nRead += (int)(n)
		if err == syscall.Errno(syscall.ENOENT) {
			break
		}
		pKey = pNextKey
	}

	flows := make([]*Flow, 0, nRead)
	for i := 0; i < nRead; i++ {
		saddr := inetNtop((uint32)(values[i].saddr))
		daddr := inetNtop((uint32)(values[i].daddr))
		flow := &Flow{
			SAddr:       &saddr,
			DAddr:       &daddr,
			ProcessName: C.GoString((*C.char)(unsafe.Pointer(&values[i].task))),
			LPort:       ntohs((uint16)(values[i].lport)),
			Direction:   FlowDirection((uint8)(values[i].direction)),
			LastPID:     (uint32)(values[i].pid),
			Stat: &FlowStat{
				NewConnections: (uint32)(values[i].stat.connections),
			},
		}
		flows = append(flows, flow)
	}

	return flows, nil
}
