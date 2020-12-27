package main

import (
	"fmt"
	"math"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

/*
#cgo CFLAGS: -I ../../src/.output
#cgo LDFLAGS: -L../../src/.output/libbpf -l:libbpf.a -lelf -lz -Wl,-rpath=../../src/.output/libbpf
#include <bpf/libbpf.h>
#include "conntracer.skel.h"
*/
import "C"

func bumpMemlockRlimit() error {
	rl := unix.Rlimit{
		Cur: math.MaxUint64,
		Max: math.MaxUint64,
	}
	err := unix.Setrlimit(unix.RLIMIT_MEMLOCK, &rl)
	if err != nil {
		return err
	}
	return nil
}

func main() {
	/* Bump RLIMIT_MEMLOCK to allow BPF sub-system to do anything */
	if err := bumpMemlockRlimit(); err != nil {
		panic(err)
	}

	obj := C.conntracer_bpf__open_and_load()
	if obj == nil {
		panic("failed to open and load BPF object\n")
	}
	defer C.free(unsafe.Pointer(obj))

	cerr := C.conntracer_bpf__attach(obj)
	if cerr != 0 {
		panic(fmt.Sprintf("failed to attach BPF programs: %s\n", C.strerror(-cerr)))
	}

	for {
		fmt.Println("Waiting...")
		time.Sleep(10 * time.Second)
	}
}
