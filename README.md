# go-conntracer-bpf

[![Go Reference](https://pkg.go.dev/badge/github.com/yuuki/go-conntracer-bpf.svg)](https://pkg.go.dev/github.com/yuuki/go-conntracer-bpf)

go-conntracer-bpf is a library for Go for tracing network connection (TCP) events (connect, accept, close) on BPF kprobe inspired by [weaveworks/tcptracer-bpf](https://github.com/weaveworks/tcptracer-bpf).

## Features

- Low-overhead tracing by aggregating connections events in kernel.
- BPF CO-RE (Compile Once – Run Everywhere)-enabled

## Requirements

### Compilation phase

- libbpf (included as git submodule)
- Clang/LLVM 10+
- libelf-dev and libz-dev packages.

### Execution phase

- Linux kernel to be built with BTF type information. See <https://github.com/libbpf/libbpf#bpf-co-re-compile-once--run-everywhere>.

## Usage

- [godoc](https://godoc.org/github.com/yuuki/go-conntracer-bpf)

## Projects using go-conntracer-bpf

- [yuuki/shawk](https://github.com/yuuki/shawk)
