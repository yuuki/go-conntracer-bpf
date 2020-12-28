# gobpf-conntracer

gobpf-conntracer is a Go library using kprobes to trace network connection (TCP) events (connect, accept, close) inspired by [weaveworks/tcptracer-bpf](https://github.com/weaveworks/tcptracer-bpf).
gobpf-conntracer optimizes performance for tracing by aggregating connections events in kernel.
