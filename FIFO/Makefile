CLANG ?= clang
CC ?= gcc
CFLAGS = -Wall -O2 -g

LIBS = -lbpf -lelf -lz

BPF_CFLAGS = -g -O2 -target bpf -D__TARGET_ARCH_x86 \
    -I/usr/include \
    -I$(shell $(CLANG) -print-resource-dir)/include \
    -I./

.PHONY: all clean

all: xdp_FIFO.o user_prog    # เป้าหมายหลัก

# Compile eBPF object
xdp_FIFO.o: xdp_FIFO.c common.h
	$(CLANG) $(BPF_CFLAGS) -c xdp_FIFO.c -o xdp_FIFO.o

# Compile userspace program
user_prog: user_prog.c common.h
	$(CC) $(CFLAGS) user_prog.c -o user_prog $(LIBS)

clean:
	rm -f xdp_FIFO.o user_prog