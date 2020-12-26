export GOOS=linux

all: build

.PHONY: build
build:
	go generate ./...
	go build -o print_traces ./... 
