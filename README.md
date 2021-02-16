# go-conntracer-bpf

[![Go Reference](https://pkg.go.dev/badge/github.com/yuuki/go-conntracer-bpf.svg)](https://pkg.go.dev/github.com/yuuki/go-conntracer-bpf)

go-conntracer-bpf is a library for Go for tracing network connection (TCP/UDP) events (connect, accept, sendto, recvfrom) on BPF kprobe inspired by [weaveworks/tcptracer-bpf](https://github.com/weaveworks/tcptracer-bpf). go-conntracer-bpf is implemented on top of [libbpf](https://github.com/libbpf/libbpf), which is a representative C library for BPF included Linux kernel.

## Features

- Low-overhead tracing by aggregating connection events in kernel.
- BPF CO-RE (Compile Once – Run Everywhere)-enabled

![Flow events aggregation in kernel](./docs/images/aggregation.png "aggregation")

## Prerequisites

### Compilation phase

- libbpf source code
- Clang/LLVM >= 9

### Runtime phase

- Linux kernel version >= 5.6 (due to batch ops to bpf maps)
- Linux kernel to be built with BTF type information. See <https://github.com/libbpf/libbpf#bpf-co-re-compile-once--run-everywhere>.

### Common to both phase

- libelf and zlib libraries

## Features of Linux kernel included in go-conntracer-bpf

go-conntracer-bpf makes use of some latest features of Linux kernel.

- BPF Type Format (BTF)	in kernel version 4.18.
- Batch API to BPF map (BPF_MAP_UPDATE_BATCH, BPF_MAP_LOOKUP_AND_DELETE_BATCH) in kernel version 5.6.
- Ring Buffer in kernel version 5.8 (only a flavor of no-aggregation in kernel).

## Usage

- [godoc](https://godoc.org/github.com/yuuki/go-conntracer-bpf)

## conntop

conntop is a CLI tool to show connection events.

### Build conntop

```shell-session
$ make DOCKER=1
```

## Projects using go-conntracer-bpf

- [yuuki/shawk](https://github.com/yuuki/shawk)
