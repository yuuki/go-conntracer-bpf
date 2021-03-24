package conntracer

import (
	"errors"
	"fmt"
	"syscall"
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
