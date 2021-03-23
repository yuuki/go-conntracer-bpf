package conntracer

/*
#cgo CFLAGS: -I${SRCDIR}/include
#cgo LDFLAGS: -lelf -lz

#include <sys/resource.h>
#include <arpa/inet.h>
#include <errno.h>

#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "conntracer_streaming.skel.h"
#include "conntracer.h"
*/
import "C"

import (
	"syscall"
	"unsafe"

	"golang.org/x/xerrors"
)

func initializeUDPPortBindingMap(fd C.int) error {
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
		fd,
		unsafe.Pointer(&ports[0]),  // keys
		unsafe.Pointer(&values[0]), // values
		&count,
		opts)
	if ret != 0 {
		return xerrors.Errorf("could not update port_bindings map: ret:%d", ret)
	}

	return nil
}
