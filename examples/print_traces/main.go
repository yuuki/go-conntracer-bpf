//go:generate go-bindata -prefix "../../src/.output" -pkg main -modtime 1 -o "./print_tracer.bindata.go" "../../src/.output/conntracer.bpf.o"

package main

import (
	"bytes"
	"fmt"
	"math"
	"time"

	"golang.org/x/sys/unix"

	"github.com/cilium/ebpf"
)

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

	obj, err := Asset("conntracer.bpf.o")	
	if err != nil {
		panic("Error load ELF object")
	}

	spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(elf))
	if err != nil {
		panic(err)
	}

	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		panic(err)
	}

	prog := coll.DetachProgram("tcp_v4_connect")
	if prog == nil {
		panic("no program named tcp_v4_connect found")
	}
	defer prog.Close()

	pinfo, _ := prog.Info()
	fmt.Printf("Program info: %+v\n", pinfo)

	for {
		fmt.Println("Waiting...")
		time.Sleep(10 * time.Second)
	}
}
