#!/bin/bash
# scripts/benchmark_qos.sh
# Full QoS Benchmark: No QoS vs HTB vs eBPF
# Tests both TCP and UDP with rate limit 500/300/200 Mbps
#
# Run on VM2 (Server): sudo bash scripts/benchmark_qos.sh
# Then follow instructions to send traffic from VM1

set -e

# ===== Configuration =====
IFACE="ens19"
SERVER_IP="192.168.1.4"
DURATION=30
BW="500M"
RESULT_DIR="results/benchmark_$(date +%Y%m%d_%H%M%S)"
BPF_OBJ="src/classifier.bpf.o"

PORT_EF=5201
PORT_AF=5202
PORT_BE=5203

EF_RATE=500   # Mbps
AF_RATE=300
BE_RATE=200

mkdir -p "$RESULT_DIR"

# ===== Helpers =====

cleanup() {
    echo "[*] Cleaning up..."
    sudo tc qdisc del dev $IFACE clsact 2>/dev/null || true
    sudo tc qdisc del dev $IFACE root 2>/dev/null || true
    pkill -f "iperf3 -s" 2>/dev/null || true
    sleep 2
}

start_servers() {
    pkill -f "iperf3 -s" 2>/dev/null || true
    sleep 1
    iperf3 -s -p $PORT_EF -D
    iperf3 -s -p $PORT_AF -D
    iperf3 -s -p $PORT_BE -D
    sleep 1
    echo "[*] iperf3 servers started on ports $PORT_EF, $PORT_AF, $PORT_BE"
}

setup_htb() {
    sudo tc qdisc del dev $IFACE root 2>/dev/null || true
    sudo tc qdisc add dev $IFACE root handle 1: htb default 30
    sudo tc class add dev $IFACE parent 1: classid 1:1 htb rate 1gbit ceil 1gbit
    sudo tc class add dev $IFACE parent 1:1 classid 1:10 htb rate ${EF_RATE}mbit ceil 1gbit prio 1
    sudo tc class add dev $IFACE parent 1:1 classid 1:20 htb rate ${AF_RATE}mbit ceil ${AF_RATE}mbit prio 2
    sudo tc class add dev $IFACE parent 1:1 classid 1:30 htb rate ${BE_RATE}mbit ceil ${BE_RATE}mbit prio 3
    sudo tc filter add dev $IFACE parent 1: protocol ip prio 1 u32 match ip tos 0xb8 0xff flowid 1:10
    sudo tc filter add dev $IFACE parent 1: protocol ip prio 2 u32 match ip tos 0x88 0xff flowid 1:20
    echo "[*] HTB configured: EF=${EF_RATE}M AF=${AF_RATE}M BE=${BE_RATE}M"
}

setup_ebpf() {
    sudo tc qdisc del dev $IFACE clsact 2>/dev/null || true
    sudo tc qdisc add dev $IFACE clsact
    sudo tc filter add dev $IFACE ingress bpf da obj $BPF_OBJ sec tc
    echo "[*] eBPF attached (ingress)"

    # Set rate configs via bpftool
    sleep 1
    # Find config_map
    local MAP_ID=$(sudo bpftool map show | grep "config_map" | head -1 | awk '{print $1}' | tr -d ':')
    if [ -n "$MAP_ID" ]; then
        # EF config: rate_bps = 500Mbps/8 = 62500000, burst = 4194304
        sudo bpftool map update id $MAP_ID key 0 0 0 0 value \
            $(python3 -c "
import struct
rate = $EF_RATE * 1000000 // 8
burst = 4 * 1024 * 1024
print(' '.join(f'{b}' for b in struct.pack('<QQ', rate, burst)))
")
        # AF config
        sudo bpftool map update id $MAP_ID key 1 0 0 0 value \
            $(python3 -c "
import struct
rate = $AF_RATE * 1000000 // 8
burst = 4 * 1024 * 1024
print(' '.join(f'{b}' for b in struct.pack('<QQ', rate, burst)))
")
        # BE config
        sudo bpftool map update id $MAP_ID key 2 0 0 0 value \
            $(python3 -c "
import struct
rate = $BE_RATE * 1000000 // 8
burst = 4 * 1024 * 1024
print(' '.join(f'{b}' for b in struct.pack('<QQ', rate, burst)))
")
        echo "[*] eBPF rate configs set: EF=${EF_RATE}M AF=${AF_RATE}M BE=${BE_RATE}M"
    else
        echo "[!] WARNING: config_map not found, rate limiting disabled"
    fi
}

run_test() {
    local scenario=$1  # no_qos, htb, ebpf
    local proto=$2     # tcp, udp
    local label="${scenario}_${proto}"
    local proto_flag=""
    
    [ "$proto" = "udp" ] && proto_flag="-u"

    echo ""
    echo "  ┌─────────────────────────────────────────────────────┐"
    echo "  │  Run on VM1 NOW ($proto):                            "
    echo "  │                                                      "
    echo "  │  iperf3 -c $SERVER_IP -p $PORT_EF $proto_flag -S 0xb8 -t $DURATION -b $BW -J > /tmp/ef_${label}.json &"
    echo "  │  iperf3 -c $SERVER_IP -p $PORT_AF $proto_flag -S 0x88 -t $DURATION -b $BW -J > /tmp/af_${label}.json &"
    echo "  │  iperf3 -c $SERVER_IP -p $PORT_BE $proto_flag         -t $DURATION -b $BW -J > /tmp/be_${label}.json &"
    echo "  │                                                      "
    echo "  └─────────────────────────────────────────────────────┘"

    # Start CPU monitoring
    mpstat -P ALL 1 $((DURATION + 10)) > "$RESULT_DIR/${label}_cpu.txt" 2>&1 &
    local mpstat_pid=$!

    read -p "  [?] Press ENTER after starting traffic on VM1... "

    echo "  [*] Waiting ${DURATION}s..."

    # Dump eBPF stats if applicable
    if [ "$scenario" = "ebpf" ]; then
        (
            sleep $((DURATION - 2))
            echo "  --- eBPF stats snapshot ---"
            sudo bpftool map dump name stats_map 2>/dev/null | grep -E '"key"|"packets"|"bytes"|"dropped"'
        ) &
    fi

    sleep $((DURATION + 5))
    kill $mpstat_pid 2>/dev/null || true

    # Save tc stats for HTB
    if [ "$scenario" = "htb" ]; then
        sudo tc -s class show dev $IFACE > "$RESULT_DIR/${label}_tc_stats.txt" 2>&1
    fi

    # Save eBPF stats
    if [ "$scenario" = "ebpf" ]; then
        sudo bpftool map dump name stats_map > "$RESULT_DIR/${label}_ebpf_stats.json" 2>/dev/null || true
    fi

    echo "  [*] Test '$label' complete"
}

# ===== Main =====

echo ""
echo "╔════════════════════════════════════════════════════════════════╗"
echo "║     Full QoS Benchmark: No QoS vs HTB vs eBPF               ║"
echo "║     Rate Policy: EF=${EF_RATE}M  AF=${AF_RATE}M  BE=${BE_RATE}M Mbps           ║"
echo "║     Duration: ${DURATION}s per test, 6 tests total                   ║"
echo "║     Results: $RESULT_DIR"
echo "╚════════════════════════════════════════════════════════════════╝"
echo ""

# ============================================================
# TEST 1: No QoS — UDP
# ============================================================
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  TEST 1/6: No QoS — UDP"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
cleanup
start_servers
run_test "no_qos" "udp"

# ============================================================
# TEST 2: No QoS — TCP
# ============================================================
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  TEST 2/6: No QoS — TCP"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
cleanup
start_servers
run_test "no_qos" "tcp"

# ============================================================
# TEST 3: HTB — UDP
# ============================================================
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  TEST 3/6: HTB — UDP"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
cleanup
start_servers
setup_htb
run_test "htb" "udp"

# ============================================================
# TEST 4: HTB — TCP
# ============================================================
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  TEST 4/6: HTB — TCP"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
cleanup
start_servers
setup_htb
run_test "htb" "tcp"

# ============================================================
# TEST 5: eBPF — UDP
# ============================================================
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  TEST 5/6: eBPF — UDP"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
cleanup
start_servers
setup_ebpf
run_test "ebpf" "udp"

# ============================================================
# TEST 6: eBPF — TCP
# ============================================================
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  TEST 6/6: eBPF — TCP"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
cleanup
start_servers
setup_ebpf
run_test "ebpf" "tcp"

# ============================================================
# Done
# ============================================================
cleanup

echo ""
echo "╔════════════════════════════════════════════════════════════════╗"
echo "║  All 6 tests complete!                                       ║"
echo "║                                                               ║"
echo "║  Results saved: $RESULT_DIR/"
echo "║                                                               ║"
echo "║  CPU files: *_cpu.txt                                         ║"
echo "║  TC stats:  htb_*_tc_stats.txt                                ║"
echo "║  eBPF stats: ebpf_*_ebpf_stats.json                          ║"
echo "║                                                               ║"
echo "║  Collect from VM1:                                            ║"
echo "║    scp 192.168.1.3:/tmp/*_no_qos*.json $RESULT_DIR/          ║"
echo "║    scp 192.168.1.3:/tmp/*_htb*.json $RESULT_DIR/             ║"
echo "║    scp 192.168.1.3:/tmp/*_ebpf*.json $RESULT_DIR/            ║"
echo "╚════════════════════════════════════════════════════════════════╝"
