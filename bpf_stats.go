package conntracer

/*
#cgo CFLAGS: -I${SRCDIR}/include
#cgo LDFLAGS: -lelf -lz

#include <bpf/libbpf.h>
#include <bpf/bpf.h>
*/
import "C"

import "golang.org/x/xerrors"

func enableBPFStats() (int, error) {
	fd, err := C.bpf_enable_stats(C.BPF_STATS_RUN_TIME)
	if err != nil {
		return 0, xerrors.Errorf("could not enable bpf stats: %s", err)
	}
	return int(fd), nil
}
