export GOOS=linux
export GOARCH=amd64
export CGO_ENABLED=1
export GODEBUG=cgocheck=2

BIN := $(abspath ./bin)
GO := $(shell which go)
SUDO := sudo -E

all: bpf/build examples/build 

.PHONY: test
test:
	$(SUDO) $(GO) test -v .

.PHONY: examples/build
examples/build:
	go generate ./...
	go build -mod vendor -o $(BIN)/print_traces ./examples/print_traces/...

.PHONY: tidy
tidy:
	go mod tidy
	go mod vendor

.PHONY: bpf/build
bpf/build:
	make -C bpf
