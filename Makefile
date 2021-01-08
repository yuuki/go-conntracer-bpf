export GOOS=linux
export GOARCH=amd64
export CGO_ENABLED=1

BIN := $(abspath ./bin)
GO := $(shell which go)
SUDO := sudo -E

.PHONY: all
all: bpf/build examples/build 

.PHONY: test
test:
	$(SUDO) $(GO) test -v .

.PHONY: examples/build
examples/build:
	go build -mod vendor -o $(BIN)/print_traces ./examples/print_traces/...

.PHONY: tidy
tidy:
	go mod tidy
	go mod vendor

.PHONY: bpf/build
bpf/build:
	make -C bpf

.PHONY: clean
	go clean -x -cache -testcache
