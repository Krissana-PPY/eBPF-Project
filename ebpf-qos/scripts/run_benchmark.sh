#!/bin/bash
# scripts/run_benchmark.sh
# Automated benchmark: No QoS vs tc+HTB vs eBPF Classifier
#
# Run on VM2 (Server). VM1 must have iperf3 installed.
# Usage: sudo bash scripts/run_benchmark.sh
#
# Prerequisites:
#   - iperf3 servers will be started automatically
#   - eBPF program must be compiled (make bpf)

set -e

# ===== Configuration =====
IFACE="ens19"
CLIENT_IP="192.168.1.3"        # VM1 IP — change if different
SERVER_IP="192.168.1.4"        # VM2 IP
DURATION=30                     # seconds per test
BW="500M"                      # bandwidth limit per flow
RESULT_DIR="results"
BPF_OBJ="src/classifier.bpf.o"

# Ports for each traffic class
PORT_EF=5201
PORT_AF=5202
PORT_BE=5203

mkdir -p $RESULT_DIR

# ===== Helper Functions =====

cleanup() {
    echo "[*] Cleaning up..."
    sudo tc qdisc del dev $IFACE clsact 2>/dev/null || true
    sudo tc qdisc del dev $IFACE root 2>/dev/null || true
    # Kill iperf3 servers
    pkill -f "iperf3 -s" 2>/dev/null || true
    sleep 1
}

start_servers() {
    echo "[*] Starting iperf3 servers on ports $PORT_EF, $PORT_AF, $PORT_BE..."
    pkill -f "iperf3 -s" 2>/dev/null || true
    sleep 1
    iperf3 -s -p $PORT_EF -D
    iperf3 -s -p $PORT_AF -D
    iperf3 -s -p $PORT_BE -D
    sleep 1
}

# Run iperf3 clients on VM1 via SSH (or print instructions)
run_traffic() {
    local label=$1
    local outfile="$RESULT_DIR/${label}"

    echo ""
    echo "============================================================"
    echo "  Please run these commands on VM1 ($CLIENT_IP) NOW:"
    echo "============================================================"
    echo ""
    echo "  # Open 3 terminals on VM1 and run simultaneously:"
    echo "  iperf3 -c $SERVER_IP -p $PORT_EF -S 0xb8 -t $DURATION -b $BW -J > /tmp/ef_${label}.json &"
    echo "  iperf3 -c $SERVER_IP -p $PORT_AF -S 0x88 -t $DURATION -b $BW -J > /tmp/af_${label}.json &"
    echo "  iperf3 -c $SERVER_IP -p $PORT_BE         -t $DURATION -b $BW -J > /tmp/be_${label}.json &"
    echo ""
    echo "  Or copy-paste this one-liner:"
    echo "  iperf3 -c $SERVER_IP -p $PORT_EF -S 0xb8 -t $DURATION -b $BW -J > /tmp/ef_${label}.json & \\"
    echo "  iperf3 -c $SERVER_IP -p $PORT_AF -S 0x88 -t $DURATION -b $BW -J > /tmp/af_${label}.json & \\"
    echo "  iperf3 -c $SERVER_IP -p $PORT_BE         -t $DURATION -b $BW -J > /tmp/be_${label}.json &"
    echo ""
    echo "============================================================"
    echo ""

    # Collect CPU stats on VM2 while traffic runs
    echo "[*] Collecting CPU stats for $DURATION seconds..."
    mpstat -P ALL 1 $((DURATION + 5)) > "${outfile}_cpu.txt" 2>&1 &
    local mpstat_pid=$!

    # Wait for user confirmation
    read -p "[?] Press ENTER when you have started traffic on VM1... "

    echo "[*] Waiting ${DURATION}s for traffic to complete..."

    # If eBPF is active, dump stats periodically
    if [ "$label" = "ebpf" ]; then
        for i in $(seq 1 $DURATION); do
            sleep 1
            if [ $((i % 10)) -eq 0 ]; then
                echo "  [$i/${DURATION}s] eBPF stats:"
                sudo bpftool map dump name stats_map 2>/dev/null | \
                    grep -A3 '"key"' | head -20
            fi
        done
    else
        sleep $DURATION
    fi

    sleep 5  # buffer
    kill $mpstat_pid 2>/dev/null || true

    echo "[*] Test '$label' complete. CPU stats saved to ${outfile}_cpu.txt"
    echo ""
}

setup_htb() {
    echo "[*] Setting up tc + HTB on $IFACE..."

    sudo tc qdisc del dev $IFACE root 2>/dev/null || true

    # HTB root
    sudo tc qdisc add dev $IFACE root handle 1: htb default 30

    # Parent: limit to 1Gbit total
    sudo tc class add dev $IFACE parent 1: classid 1:1 \
        htb rate 1gbit ceil 1gbit

    # EF: 500Mbit guaranteed, highest priority
    sudo tc class add dev $IFACE parent 1:1 classid 1:10 \
        htb rate 500mbit ceil 1gbit prio 1

    # AF: 300Mbit guaranteed
    sudo tc class add dev $IFACE parent 1:1 classid 1:20 \
        htb rate 300mbit ceil 1gbit prio 2

    # BE: 200Mbit guaranteed, lowest priority
    sudo tc class add dev $IFACE parent 1:1 classid 1:30 \
        htb rate 200mbit ceil 1gbit prio 3

    # DSCP filters
    sudo tc filter add dev $IFACE parent 1: protocol ip prio 1 \
        u32 match ip tos 0xb8 0xff flowid 1:10

    sudo tc filter add dev $IFACE parent 1: protocol ip prio 2 \
        u32 match ip tos 0x88 0xff flowid 1:20

    echo "[*] HTB configured:"
    sudo tc -s class show dev $IFACE | head -30
}

setup_ebpf() {
    echo "[*] Setting up eBPF classifier on $IFACE..."

    sudo tc qdisc del dev $IFACE clsact 2>/dev/null || true
    sudo tc qdisc add dev $IFACE clsact
    sudo tc filter add dev $IFACE egress bpf da obj $BPF_OBJ sec tc

    echo "[*] eBPF attached:"
    sudo tc filter show dev $IFACE egress
}

# ===== Main =====

echo "╔══════════════════════════════════════════════════════════════╗"
echo "║         eBPF QoS Benchmark — 3 Scenarios                   ║"
echo "║         Duration: ${DURATION}s per test, BW: ${BW} per flow          ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo ""

start_servers

# ----- Test 1: No QoS -----
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  TEST 1/3: No QoS (baseline)"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
cleanup
run_traffic "no_qos"

# ----- Test 2: tc + HTB -----
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  TEST 2/3: tc + HTB (traditional QoS)"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
cleanup
start_servers
setup_htb
run_traffic "htb"

# ----- Test 3: eBPF -----
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  TEST 3/3: eBPF classifier"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
cleanup
start_servers
setup_ebpf
run_traffic "ebpf"

# ----- Done -----
cleanup

echo ""
echo "╔══════════════════════════════════════════════════════════════╗"
echo "║  All tests complete!                                       ║"
echo "║  Results saved in: $RESULT_DIR/                            ║"
echo "║                                                            ║"
echo "║  Files:                                                    ║"
echo "║    no_qos_cpu.txt  — CPU stats without QoS                 ║"
echo "║    htb_cpu.txt     — CPU stats with tc+HTB                 ║"
echo "║    ebpf_cpu.txt    — CPU stats with eBPF classifier        ║"
echo "║                                                            ║"
echo "║  Also collect from VM1:                                    ║"
echo "║    /tmp/ef_*.json, /tmp/af_*.json, /tmp/be_*.json          ║"
echo "╚══════════════════════════════════════════════════════════════╝"
