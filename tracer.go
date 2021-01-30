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
	"golang.org/x/xerrors"
)

/*
#cgo CFLAGS: -I${SRCDIR}/includes
#cgo LDFLAGS: -lelf -lz

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
	FlowUnknown FlowDirection = iota + 1
	// FlowActive are 'active open'.
	FlowActive
	// FlowPassive are 'passive open'
	FlowPassive

	// defaultFlowMapOpsBatchSize is batch size of BPF map(flows) lookup_and_delete.
	defaultFlowMapOpsBatchSize = 10

	populateListeningPortsInterval = 5 * time.Second
)

func flowDirectionFrom(x C.flow_direction) FlowDirection {
	switch x {
	case C.FLOW_UNKNOWN:
		return FlowUnknown
	case C.FLOW_ACTIVE:
		return FlowActive
	case C.FLOW_PASSIVE:
		return FlowPassive
	}
	return FlowUnknown
}

// Flow is a bunch of aggregated connections group by listening port.
type Flow struct {
	SAddr       *net.IP
	DAddr       *net.IP
	ProcessName string
	LPort       uint16 // Listening port
	Direction   FlowDirection
	LastPID     uint32
	L4Proto     uint8
	Stat        *FlowStat
}

// FlowStat is an statistics for Flow.
type FlowStat struct {
	NewConnections uint32
}

// Tracer is an object for state retention.
type Tracer struct {
	obj                    *C.struct_conntracer_bpf
	stopChan               chan struct{}
	stopPopulateLPortsChan chan struct{}

	// option
	batchSize int
}

// NewTracer creates a Tracer object.
func NewTracer() (*Tracer, error) {
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

	t := &Tracer{
		obj:                    obj,
		stopChan:               make(chan struct{}),
		stopPopulateLPortsChan: make(chan struct{}),
		batchSize:              defaultFlowMapOpsBatchSize,
	}
	return t, nil
}

// Close closes tracer.
func (t *Tracer) Close() {
	close(t.stopChan)
	close(t.stopPopulateLPortsChan)
	C.conntracer_bpf__destroy(t.obj)
}

// Start starts polling loop.
func (t *Tracer) Start(cb func([]*Flow) error, interval time.Duration) {
	t.initializeUDPPortBindingMap()
	go t.pollFlows(cb, interval)
}

// Stop stops polling loop.
func (t *Tracer) Stop() {
	t.stopChan <- struct{}{}
	t.stopPopulateLPortsChan <- struct{}{}
}

// DumpFlows gets and deletes all flows.
func (t *Tracer) DumpFlows() ([]*Flow, error) {
	return dumpFlows(t.flowsMapFD())
}

func (t *Tracer) flowsMapFD() C.int {
	return C.bpf_map__fd(t.obj.maps.flows)
}

func (t *Tracer) udpPortBindingMapFD() C.int {
	return C.bpf_map__fd(t.obj.maps.udp_port_binding)
}

func (t *Tracer) pollFlows(cb func([]*Flow) error, interval time.Duration) {
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
		ret, err = C.bpf_map_lookup_and_delete_batch(fd, pKey, pNextKey,
			unsafe.Pointer(uintptr(ckeys)+uintptr(nRead*C.sizeof_struct_ipv4_flow_key)),
			unsafe.Pointer(uintptr(cvalues)+uintptr(nRead*C.sizeof_struct_flow)),
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
			Direction:   flowDirectionFrom((C.flow_direction)(values[i].direction)),
			L4Proto:     (uint8)(ntohs((uint16)(values[i].l4_proto))),
			LastPID:     (uint32)(values[i].pid),
			Stat: &FlowStat{
				NewConnections: (uint32)(values[i].stat.connections),
			},
		}
		flows = append(flows, flow)
	}

	return flows, nil
}

func (t *Tracer) initializeUDPPortBindingMap() error {
	ports, err := getLocalListeningPorts(syscall.IPPROTO_UDP)
	if err != nil {
		return err
	}

	keys := make([]C.struct_port_binding_key, len(ports))
	for i := range keys {
		keys[i].port = (C.ushort)(ports[i])
	}
	values := make([]uint32, len(ports))
	for i := range values {
		values[i] = C.PORT_LISTENING
	}
	count := (C.uint)(len(ports))
	opts := &C.struct_bpf_map_batch_opts{
		elem_flags: C.BPF_ANY,
		flags:      0,
		sz:         C.sizeof_struct_bpf_map_batch_opts,
	}
	ret := C.bpf_map_update_batch(
		t.udpPortBindingMapFD(),
		unsafe.Pointer(&ports[0]),  // keys
		unsafe.Pointer(&values[0]), // values
		&count,
		opts)
	if ret != 0 {
		return xerrors.Errorf("could not update port_bindings map: ret:%d", ret)
	}

	return nil
}
