export GOOS=linux

all: build

.PHONY: build
build:
	go generate ./...
	go build -mod vendor -o print_traces ./examples/print_traces/...
