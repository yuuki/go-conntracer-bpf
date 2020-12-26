package main

import (
	"bytes"
	"fmt"
	"io/ioutil"

	"github.com/cilium/ebpf"
)

const BPF_ELF_FILE = "src/.output/conntracer.bpf.o"

func main() {
	elf, err := ioutil.ReadFile(BPF_ELF_FILE)
	if err != nil {
		panic("Error reading BPF program:" + err.Error())
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
