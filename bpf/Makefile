# bpf/Makefile : CO-RE eBPF 빌드 (커널 내부 헤더 불필요)
BPF_CLANG      ?= clang
BPF_LLVM_STRIP ?= llvm-strip

UNAME_M := $(shell uname -m)
ifeq ($(UNAME_M),x86_64)
  BPF_TARGET := x86
else ifeq ($(UNAME_M),aarch64)
  BPF_TARGET := arm64
else
  $(error Unsupported arch $(UNAME_M))
endif

CFLAGS := -O2 -g -Wall -Werror -target bpf -D__TARGET_ARCH_$(BPF_TARGET) \
          -fvisibility=hidden -fno-asynchronous-unwind-tables -fno-stack-protector

BPF_SRCS := tc_hier_pubsub_kern.c
BPF_HDRS := commons.h vmlinux.h
BPF_OBJS := $(BPF_SRCS:.c=.o)

.PHONY: all clean
all: $(BPF_OBJS)

# 커널 BTF에서 vmlinux.h 생성 (한 번만)
vmlinux.h:
	@which bpftool >/dev/null || (echo "bpftool not found. Install it."; exit 1)
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > $@

%.o: %.c $(BPF_HDRS)
	$(BPF_CLANG) $(CFLAGS) -c $< -o $@
	$(BPF_LLVM_STRIP) -g $@

clean:
	rm -f $(BPF_OBJS) vmlinux.h
