GO := $(shell which go)
TOOL_BIN := printconn
SUDO := sudo -E
OUTPUT := .output
CLANG ?= clang
LLVM_STRIP ?= llvm-strip
BPFTOOL ?= $(abspath ../tools/bpftool)
LIBBPF_SRC := $(abspath libbpf/src)
LIBBPF_OBJ := $(abspath $(OUTPUT)/libbpf.a)
INCLUDES_DIR := $(abspath includes)
INCLUDES := -I$(OUTPUT) -I$(INCLUDES_DIR)
CFLAGS := -g -Wall
ARCH_UNAME := $(shell uname -m)
ARCH ?= $(ARCH_UNAME:aarch64=arm64)

DEBUG ?= 1

.PHONY: all
all: $(TOOL_BIN)

#--- libbpf ---

$(LIBBPF_SRC):
	test -d $(LIBBPF_SRC) || git submodule update --init || (echo "missing libbpf source" ; false)

$(OUTPUT) $(OUTPUT)/libbpf:
	@mkdir -p $@

# Build libbpf
$(LIBBPF_OBJ): $(wildcard $(LIBBPF_SRC)/*.[ch] $(LIBBPF_SRC)/Makefile) | $(OUTPUT)/libbpf
	$(MAKE) -C $(LIBBPF_SRC) BUILD_STATIC_ONLY=1                      \
			OBJDIR=$(dir $@)/libbpf DESTDIR=$(dir $@)                     \
			INCLUDEDIR= LIBDIR= UAPIDIR=                          \
			install
	@ranlib $@

#--- Kernel-space code --- 

# Build BPF code
linux_arch := $(ARCH:x86_64=x86)
$(OUTPUT)/%.bpf.o: %.bpf.c $(LIBBPF_OBJ) $(wildcard %.h) vmlinux.h | $(OUTPUT)
	@$(CLANG) -g -O2 -target bpf -fPIE -D__TARGET_ARCH_$(linux_arch) -DDEBUG=$(DEBUG) $(INCLUDES) -c $(filter %.c,$^) -o $@
	@$(LLVM_STRIP) -g $@ # strip useless DWARF info

# Generate BPF skeletons
$(INCLUDES_DIR)/%.skel.h: $(OUTPUT)/%.bpf.o | $(OUTPUT)
	@$(BPFTOOL) gen skeleton $< > $@
	@cp $@ $(INCLUDES_DIR)/

#--- User-space code --- 

go_env := GOOS=linux GOARCH=$(ARCH:x86_64=amd64) CGO_CFLAGS="-I $(INCLUDES_DIR)" CGO_LDFLAGS="$(abspath $(LIBBPF_OBJ)) -lelf -lz"

$(patsubst %,$(OUTPUT)/%.o,$(TOOL_BIN)): %.o: %.skel.h

$(TOOL_BIN): %: $(LIBBPF_OBJ)
	$(go_env) go build -mod vendor ./tools/$@

.PHONY: test
test: $(LIBBPF_OBJ)
	$(go_env) $(SUDO) $(GO) test -v .

.PHONY: tidy
tidy:
	go mod tidy
	go mod vendor

.PHONY: clean
clean:
	rm -rf $(OUTPUT) printconn
	go clean -x -cache -testcache >/dev/null
