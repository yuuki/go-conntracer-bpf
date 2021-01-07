# go-conntracer-bpf

go-conntracer-bpf is a Go library using kprobes to trace network connection (TCP) events (connect, accept, close) inspired by [weaveworks/tcptracer-bpf](https://github.com/weaveworks/tcptracer-bpf).
go-conntracer-bpf realizes low-overhead tracing by aggregating connections events in kernel.
