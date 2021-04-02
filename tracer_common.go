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
	"errors"
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

func dumpBpfMap(mapFD C.int, keys unsafe.Pointer, keySize uint32,
	values unsafe.Pointer, valueSize uint32, step uint32) (uint32, error) {
	var (
		err     error
		n       C.uint = 0
		nRead   uint32 = 0
		key            = 1 // The value can be anything
		in, out        = C.NULL, unsafe.Pointer(&key)
		opts           = &C.struct_bpf_map_batch_opts{
			elem_flags: 0,
			flags:      0,
			sz:         C.sizeof_struct_bpf_map_batch_opts,
		}
	)

	for err == nil {
		n = (C.uint)(step)
		_, err = C.bpf_map_lookup_and_delete_batch(mapFD,
			in,
			out,
			unsafe.Pointer(uintptr(keys)+uintptr(keySize*nRead)),
			unsafe.Pointer(uintptr(values)+uintptr(valueSize*nRead)),
			&n, opts)
		if err != nil && !errors.Is(err, syscall.ENOENT) {
			return 0, xerrors.Errorf(
				"Error of bpf_map_lookup_and_delete_batch, map_fd:%d: %w", mapFD, err)
		}
		nRead += (uint32)(n)
		in = out
	}

	return nRead, nil
}
