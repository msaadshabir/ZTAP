# Makefile for compiling eBPF programs

CLANG ?= clang
LLC ?= llc
BPFTOOL ?= bpftool

# Kernel headers path (adjust as needed)
KERNEL_HEADERS ?= /usr/src/linux-headers-$(shell uname -r)
LIBBPF_HEADERS ?= /usr/include

# Flags for BPF target (avoid x86 inline asm from kernel headers)
CLANG_FLAGS = -O2 -target bpf -c \
	-D__KERNEL__ -D__BPF_TRACING__ \
	-Wno-unknown-attributes \
	-Wno-unused-value -Wno-pointer-sign \
	-Wno-compare-distinct-pointer-types \
	-Wno-address-of-packed-member \
	-I$(KERNEL_HEADERS)/include/uapi \
	-I$(KERNEL_HEADERS)/include/generated/uapi \
	-I$(LIBBPF_HEADERS)

all: filter.o

filter.o: filter.c
	$(CLANG) $(CLANG_FLAGS) -o $@ $<

clean:
	rm -f *.o

verify: filter.o
	llvm-objdump -S filter.o

.PHONY: all clean verify
