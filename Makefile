export GOOS=linux
export GOARCH=amd64
export CGO_ENABLED=1

BIN := $(abspath ./bin)
GO := $(shell which go)
SUDO := sudo -E
LIBBPF_SRC := libbpf/src

.PHONY: all
all: bpf/build examples/build 

$(LIBBPF_SRC):
	test -d $(LIBBPF_SRC) || git submodule update --init || (echo "missing libbpf source" ; false)

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
bpf/build: $(LIBBPF_SRC)
	make -C bpf

.PHONY: clean
clean:
	go clean -x -cache -testcache
