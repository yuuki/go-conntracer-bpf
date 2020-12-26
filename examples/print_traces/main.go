//go:generate go-bindata -prefix "../../src/.output" -pkg main -modtime 1 -o "./print_tracer.bindata.go" "../../src/.output/conntracer.bpf.o"

package main

import (
	"bytes"
	"fmt"

	"github.com/cilium/ebpf"
)

func main() {
	elf, err := Asset("conntracer.bpf.o")	
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

	fmt.Println("Program file descriptor: ", prog.FD())
}
