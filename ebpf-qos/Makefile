# Makefile for eBPF QoS Packet Scheduling
#
# Targets:
#   make         — build everything
#   make bpf     — compile eBPF program only
#   make loader  — compile userspace loader only
#   make run     — attach to ens18 and start monitoring
#   make clean   — remove all build artifacts
#   make test    — quick test: attach, wait 10s, show stats, detach

CLANG      := clang
CC         := gcc
BPFTOOL    := bpftool

# Flags for eBPF compilation
BPF_CFLAGS := -O2 -g -target bpf -D__TARGET_ARCH_x86 \
              -I/usr/include/x86_64-linux-gnu \
              -I./include \
              -Wall

# Flags for userspace compilation
LOADER_CFLAGS  := -O2 -g -Wall -I./include
LOADER_LDFLAGS := -lbpf -lelf -lz

# Default settings
IFACE      := ens19
DIRECTION  := egress

# ===== Targets =====

.PHONY: all bpf loader clean run stop test

all: bpf loader

# --- eBPF program ---
bpf: src/classifier.bpf.o

src/classifier.bpf.o: src/classifier.bpf.c include/common.h
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@
	@echo ""
	@echo "✓ eBPF program compiled: $@"
	@echo "  Verifying with llvm-objdump..."
	@llvm-objdump -S $@ | head -5
	@echo ""

# --- Userspace loader ---
loader: src/loader

src/loader: src/loader.c include/common.h
	$(CC) $(LOADER_CFLAGS) $< -o $@ $(LOADER_LDFLAGS)
	@echo ""
	@echo "✓ Loader compiled: $@"
	@echo ""

# --- Run ---
run: all
	@echo "Starting eBPF QoS Shaping on $(IFACE) ($(DIRECTION))..."
	sudo ./src/loader $(IFACE) $(DIRECTION)

# --- Stop (cleanup) ---
stop:
	sudo tc qdisc del dev $(IFACE) clsact 2>/dev/null || true
	sudo tc qdisc replace dev $(IFACE) root fq_codel 2>/dev/null || true
	@echo "✓ Cleaned up, restored fq_codel on $(IFACE)"

# --- Quick test ---
test: all
	@echo "=== Quick Test: Attach eBPF classifier to $(IFACE) ==="
	@echo ""
	@# Attach
	sudo tc qdisc del dev $(IFACE) clsact 2>/dev/null || true
	sudo tc qdisc add dev $(IFACE) clsact
	sudo tc filter add dev $(IFACE) egress bpf da obj src/classifier.bpf.o sec tc
	@echo "✓ Attached"
	@echo ""
	@# Show TC status
	@echo "=== TC Status ==="
	sudo tc filter show dev $(IFACE) egress
	@echo ""
	@# Wait for some traffic
	@echo "Waiting 5 seconds for traffic..."
	@sleep 5
	@echo ""
	@# Show map contents
	@echo "=== Stats Map Contents ==="
	sudo bpftool map dump name stats_map 2>/dev/null || echo "(map not found — try 'make run' instead)"
	@echo ""
	@# Cleanup
	sudo tc qdisc del dev $(IFACE) clsact
	@echo "✓ Detached and cleaned up"

# --- Clean ---
clean:
	rm -f src/*.o src/loader
	@echo "✓ Cleaned"
