package conntracer

import (
	"errors"
	"fmt"
	"log"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sync/errgroup"
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
func (t *TracerInFlowAggr) Start(cb func([]*SingleFlow) error, interval time.Duration) error {
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
func (t *TracerInFlowAggr) DumpFlows() ([]*SingleFlow, error) {
	eg := errgroup.Group{}
	flowChan := make(chan map[SingleFlowTuple]*SingleFlow, 1)
	statChan := make(chan map[SingleFlowTuple]*SingleFlowStat, 1)
	eg.Go(func() error {
		flow, err := dumpSingleFlows(t.flowsMapFD())
		if err != nil {
			return err
		}
		flowChan <- flow
		close(flowChan)
		return nil
	})
	eg.Go(func() error {
		stats, err := dumpSingleFlowStats(t.flowStatsMapFD())
		if err != nil {
			return err
		}
		statChan <- stats
		close(statChan)
		return nil
	})
	if err := eg.Wait(); err != nil {
		return nil, err
	}

	// merge two maps
	flows := <-flowChan
	stats := <-statChan
	merged := make([]*SingleFlow, 0, len(flows))
	for t, flow := range flows {
		flow.Stat = stats[t]
		merged = append(merged, flow)
	}
	return merged, nil
}

func (t *TracerInFlowAggr) flowsMapFD() C.int {
	return C.bpf_map__fd(t.obj.maps.flows)
}

func (t *TracerInFlowAggr) flowStatsMapFD() C.int {
	return C.bpf_map__fd(t.obj.maps.flow_stats)
}

func (t *TracerInFlowAggr) udpPortBindingMapFD() C.int {
	return C.bpf_map__fd(t.obj.maps.udp_port_binding)
}

func (t *TracerInFlowAggr) pollFlows(cb func([]*SingleFlow) error, interval time.Duration) {
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

func dumpSingleFlowStats(fd C.int) (map[SingleFlowTuple]*SingleFlowStat, error) {
	keys := make([]C.struct_flow_tuple, C.MAX_SINGLE_FLOW_ENTRIES)
	values := make([]C.struct_single_flow_stat, C.MAX_SINGLE_FLOW_ENTRIES)

	nRead, err := dumpBpfMap(fd,
		unsafe.Pointer(&keys[0]), C.sizeof_struct_flow_tuple,
		unsafe.Pointer(&values[0]), C.sizeof_struct_single_flow_stat,
		defaultFlowMapOpsBatchSize)
	if err != nil {
		return nil, err
	}

	stats := make(map[SingleFlowTuple]*SingleFlowStat, nRead)
	for i := uint32(0); i < nRead; i++ {
		tuple := (SingleFlowTuple)(keys[i])
		stat := values[i]
		stats[tuple] = &SingleFlowStat{
			Timestamp: time.Unix((int64)(stat.ts_us)*1000*1000, 0),
			sentBytes: (uint64)(stat.sent_bytes),
			recvBytes: (uint64)(stat.recv_bytes),
		}
	}

	return stats, nil
}

func dumpSingleFlows(fd C.int) (map[SingleFlowTuple]*SingleFlow, error) {
	keys := make([]C.struct_flow_tuple, C.MAX_SINGLE_FLOW_ENTRIES)
	values := make([]C.struct_single_flow, C.MAX_SINGLE_FLOW_ENTRIES)

	nRead, err := dumpBpfMap(fd,
		unsafe.Pointer(&keys[0]), C.sizeof_struct_flow_tuple,
		unsafe.Pointer(&values[0]), C.sizeof_struct_single_flow,
		defaultFlowMapOpsBatchSize)
	if err != nil {
		return nil, err
	}

	flows := make(map[SingleFlowTuple]*SingleFlow, nRead)
	for i := uint32(0); i < nRead; i++ {
		tuple := (SingleFlowTuple)(keys[i])
		saddr := inetNtop((uint32)(values[i].saddr))
		daddr := inetNtop((uint32)(values[i].daddr))
		flows[tuple] = &SingleFlow{
			SAddr:       &saddr,
			DAddr:       &daddr,
			ProcessName: C.GoString((*C.char)(unsafe.Pointer(&values[i].task))),
			SPort:       ntohs((uint16)(values[i].sport)),
			DPort:       ntohs((uint16)(values[i].dport)),
			LPort:       ntohs((uint16)(values[i].lport)),
			Direction:   flowDirectionFrom((C.flow_direction)(values[i].direction)),
			L4Proto:     (uint8)(ntohs((uint16)(values[i].l4_proto))),
			PID:         (uint32)(values[i].pid),
			Stat:        nil,
		}
	}

	return flows, nil
}

// GetStats fetches stats of BPF program.
func (t *TracerInFlowAggr) GetStats() (map[int]*BpfProgramStats, error) {
	return getBPFAllStats(t.obj.obj)
}
