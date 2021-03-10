package conntracer

/*
#cgo CFLAGS: -I${SRCDIR}/include
#cgo LDFLAGS: -lelf -lz

#include <bpf/libbpf.h>
#include <bpf/bpf.h>
*/
import "C"

import (
	"time"
	"unsafe"

	"golang.org/x/xerrors"
)

// BpfProgramStats is a stattistics of BPF program.
type BpfProgramStats struct {
	Name     string        `json:"name"`
	RunCount uint          `json:"run_count"`
	RunTime  time.Duration `json:"run_time"`
}

func enableBPFStats() (int, error) {
	fd, err := C.bpf_enable_stats(C.BPF_STATS_RUN_TIME)
	if err != nil {
		return 0, xerrors.Errorf("could not enable bpf stats: %s", err)
	}
	return int(fd), nil
}

func getProgramStats(fd int, name string) (*BpfProgramStats, error) {
	info := C.struct_bpf_prog_info{}
	infolen := C.uint(unsafe.Sizeof(info))
	_, err := C.bpf_obj_get_info_by_fd(C.int(fd), unsafe.Pointer(&info), &infolen)
	if err != nil {
		return nil, xerrors.Errorf("could not get bpf info (fd:%d): %w", fd, err)
	}
	return &BpfProgramStats{
		Name:     name,
		RunCount: uint(info.run_cnt),
		RunTime:  time.Duration(info.run_time_ns),
	}, nil
}
