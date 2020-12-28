export GOOS=linux
export GOARCH=amd64
export CGO_ENABLED=1
export CC=clang
export GODEBUG=cgocheck=2

all: build

.PHONY: build
build:
	go generate ./...
	go build -mod vendor -o print_traces ./examples/print_traces/...

.PHONY: tidy
tidy:
	go mod tidy
	go mod vendor
