# Makefile for compiling eBPF programs

CLANG ?= clang
LLC ?= llc
BPFTOOL ?= bpftool

# Flags for BPF target (self-contained, no kernel headers needed)
CLANG_FLAGS = -O2 -target bpf -g -c \
	-D__KERNEL__ \
	-Wno-unknown-attributes \
	-Wno-unused-value -Wno-pointer-sign \
	-Wno-compare-distinct-pointer-types \
	-Wno-address-of-packed-member

all: filter.o

filter.o: filter.c
	$(CLANG) $(CLANG_FLAGS) -o $@ $<

clean:
	rm -f *.o

verify: filter.o
	llvm-objdump -S filter.o

.PHONY: all clean verify
