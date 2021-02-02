package conntracer

/*
#cgo CFLAGS: -I${SRCDIR}/include
#cgo LDFLAGS: -lelf -lz

#include <sys/resource.h>
#include <arpa/inet.h>
#include <errno.h>

#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "conntracer_without_aggr.skel.h"
#include "conntracer.h"

// The gateway function for function pointer callbacks
// https://github.com/golang/go/wiki/cgo#function-pointer-callbacks
int handle_flow_cgo(void *ctx, void *data, size_t data_sz) {
	return handleFlow(ctx, data, data_sz);
}
*/
import "C"

import (
	"errors"
	"fmt"
	"unsafe"
)

// TracerWithoutAggr is an object for state retention without aggregation.
type TracerWithoutAggr struct {
	obj *C.struct_conntracer_without_aggr_bpf
	rb  *C.struct_ring_buffer

	stopChan chan struct{}
}

// NewTracerWithoutAggr loads tracer without aggregation
func NewTracerWithoutAggr() (*TracerWithoutAggr, error) {
	// Bump RLIMIT_MEMLOCK to allow BPF sub-system to do anything
	if err := bumpMemlockRlimit(); err != nil {
		return nil, err
	}

	obj := C.conntracer_without_aggr_bpf__open_and_load()
	if obj == nil {
		return nil, errors.New("failed to open and load BPF object")
	}

	ret, err := C.conntracer_without_aggr_bpf__attach(obj)
	if ret != 0 {
		C.conntracer_without_aggr_bpf__destroy(obj)
		return nil, fmt.Errorf("failed to attach BPF programs: %v", err)
	}

	// Set up BPF ring buffer polling.
	rb := C.ring_buffer__new(
		C.bpf_map__fd(obj.maps.flows),
		(C.ring_buffer_sample_fn)(unsafe.Pointer(C.handle_flow_cgo)),
		nil, nil)
	if rb == nil {
		return nil, fmt.Errorf("failed to create ring buffer")
	}

	stopChan := make(chan struct{})

	return &TracerWithoutAggr{obj: obj, rb: rb, stopChan: stopChan}, nil
}

// TODO: sync.Pool
var globalFlowChan chan *Flow

// Start starts loop of polling events from kernel.
func (t *TracerWithoutAggr) Start(fc chan *Flow) error {
	globalFlowChan = fc

	for {
		select {
		case <-t.stopChan:
			return nil
		default:
		}

		ret, err := C.ring_buffer__poll(t.rb, 100 /* timeout, ms */)
		/* Ctrl-C will cause -EINTR */
		if ret == -C.EINTR {
			break
		}
		if ret < 0 {
			return fmt.Errorf("error polling ring buffer: %s", err)
		}
	}
	return nil
}

// Stop stop loop of polling events.
func (t *TracerWithoutAggr) Stop() {
	t.stopChan <- struct{}{}
}

// Close closes tracer.
func (t *TracerWithoutAggr) Close() {
	close(t.stopChan)
	C.conntracer_without_aggr_bpf__destroy(t.obj)
}
