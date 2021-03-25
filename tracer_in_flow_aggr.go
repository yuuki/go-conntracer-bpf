package conntracer

import (
	"errors"
	"fmt"
	"log"
	"syscall"
	"time"
	"unsafe"
)

/*
#cgo CFLAGS: -I${SRCDIR}/include
#cgo LDFLAGS: -lelf -lz

#include <sys/resource.h>
#include <arpa/inet.h>
#include <errno.h>

#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "conntracer_in_flow_aggr.skel.h"
#include "conntracer.h"

*/
import "C"

type TracerInFlowAggr struct {
	obj      *C.struct_conntracer_in_flow_aggr_bpf
	stopChan chan struct{}
	statsFd  int
}

// NewTracerInFlowAggr loads tracer with in-flow aggregation
func NewTracerInFlowAggr(param *TracerParam) (*TracerInFlowAggr, error) {
	// Bump RLIMIT_MEMLOCK to allow BPF sub-system to do anything
	if err := bumpMemlockRlimit(); err != nil {
		return nil, err
	}

	obj := C.conntracer_in_flow_aggr_bpf__open_and_load()
	if obj == nil {
		return nil, errors.New("failed to open and load BPF object")
	}

	ret, err := C.conntracer_in_flow_aggr_bpf__attach(obj)
	if ret != 0 {
		C.conntracer_in_flow_aggr_bpf__destroy(obj)
		return nil, fmt.Errorf("failed to attach BPF programs: %v", err)
	}

	t := &TracerInFlowAggr{
		obj:      obj,
		stopChan: make(chan struct{}),
	}

	if param.Stats {
		fd, err := enableBPFStats()
		if err != nil {
			return nil, err
		}
		t.statsFd = fd
	}

	return t, nil
}

func (t *TracerInFlowAggr) Close() {
	close(t.stopChan)
	if t.statsFd != 0 {
		syscall.Close(t.statsFd)
	}
	C.conntracer_in_flow_aggr_bpf__destroy(t.obj)
}

// Start starts polling loop.
func (t *TracerInFlowAggr) Start(cb func([]*Flow) error, interval time.Duration) error {
	if err := initializeUDPPortBindingMap(t.udpPortBindingMapFD()); err != nil {
		return err
	}
	go t.pollFlows(cb, interval)
	return nil
}

// Stop stops polling loop.
func (t *TracerInFlowAggr) Stop() {
	t.stopChan <- struct{}{}
}

// DumpFlows gets and deletes all flows.
func (t *TracerInFlowAggr) DumpFlows() ([]*Flow, error) {
	return dumpSingleFlows(t.flowsMapFD())
}

func (t *TracerInFlowAggr) flowsMapFD() C.int {
	return C.bpf_map__fd(t.obj.maps.flows)
}

func (t *TracerInFlowAggr) udpPortBindingMapFD() C.int {
	return C.bpf_map__fd(t.obj.maps.udp_port_binding)
}

func (t *TracerInFlowAggr) pollFlows(cb func([]*Flow) error, interval time.Duration) {
	tick := time.NewTicker(interval)
	defer tick.Stop()

	for {
		select {
		case <-t.stopChan:
			return
		case <-tick.C:
			flows, err := t.DumpFlows()
			if err != nil {
				log.Println(err)
			}
			if err := cb(flows); err != nil {
				log.Println(err)
			}
		}
	}
}

func dumpSingleFlows(fd C.int) ([]*Flow, error) {
	pKey, pNextKey := C.NULL, unsafe.Pointer(&C.struct_flow_tuple{})
	keys := make([]C.struct_flow_tuple, C.MAX_SINGLE_FLOW_ENTRIES)
	ckeys := unsafe.Pointer(&keys[0])
	values := make([]C.struct_single_flow, C.MAX_SINGLE_FLOW_ENTRIES)
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
		ret, err = C.bpf_map_lookup_and_delete_batch(fd, pKey, pNextKey,
			unsafe.Pointer(uintptr(ckeys)+uintptr(nRead*C.sizeof_struct_flow_tuple)),
			unsafe.Pointer(uintptr(cvalues)+uintptr(nRead*C.sizeof_struct_single_flow)),
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
			LPort:       (uint16)(values[i].lport), // why not ntohs?
			Direction:   flowDirectionFrom((C.flow_direction)(values[i].direction)),
			L4Proto:     (uint8)(ntohs((uint16)(values[i].l4_proto))),
			LastPID:     (uint32)(values[i].pid),
			Stat:        &FlowStat{}, // %TODO:
		}
		flows = append(flows, flow)
	}

	return flows, nil
}

// GetStats fetches stats of BPF program.
func (t *TracerInFlowAggr) GetStats() (map[int]*BpfProgramStats, error) {
	res := map[int]*BpfProgramStats{}
	for prog := C.bpf_program__next(nil, t.obj.obj); prog != nil; prog = C.bpf_program__next((*C.struct_bpf_program)(prog), t.obj.obj) {
		fd := int(C.bpf_program__fd(prog))
		name := C.GoString(C.bpf_program__name(prog))
		stats, err := getProgramStats(fd, name)
		if err != nil {
			return nil, err
		}
		res[fd] = stats
	}
	return res, nil
}
