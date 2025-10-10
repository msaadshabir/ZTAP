# Makefile for compiling eBPF programs

CLANG ?= clang
LLC ?= llc
BPFTOOL ?= bpftool

# Kernel headers path (adjust as needed)
KERNEL_HEADERS ?= /usr/src/linux-headers-$(shell uname -r)
LIBBPF_HEADERS ?= /usr/include

# Flags
CLANG_FLAGS = -O2 -target bpf -c \
	-D__KERNEL__ -D__BPF_TRACING__ \
	-Wno-unused-value -Wno-pointer-sign \
	-Wno-compare-distinct-pointer-types \
	-I$(KERNEL_HEADERS)/include \
	-I$(KERNEL_HEADERS)/include/uapi \
	-I$(KERNEL_HEADERS)/include/generated/uapi \
	-I$(KERNEL_HEADERS)/arch/x86/include \
	-I$(KERNEL_HEADERS)/arch/x86/include/uapi \
	-I$(KERNEL_HEADERS)/arch/x86/include/generated \
	-I$(LIBBPF_HEADERS)

all: filter.o

filter.o: filter.c
	$(CLANG) $(CLANG_FLAGS) -o $@ $<

clean:
	rm -f *.o

verify: filter.o
	llvm-objdump -S filter.o

.PHONY: all clean verify
