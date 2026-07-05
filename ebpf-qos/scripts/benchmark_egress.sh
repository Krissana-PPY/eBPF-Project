#!/bin/bash
# scripts/benchmark_egress.sh
# Fair Egress Benchmark: No QoS vs HTB vs eBPF
# Both HTB and eBPF work at EGRESS — fair comparison
#
# Key difference from previous test:
#   VM1 = iperf3 SERVER (receiver)
#   VM2 = iperf3 CLIENT (sender) + eBPF/HTB at egress
#
# This way data packets flow OUT through egress on VM2
# where both HTB and eBPF can control them fairly
#
# Run on VM2: sudo bash scripts/benchmark_egress.sh

set -e

IFACE="ens19"
CLIENT_IP="192.168.1.3"   # VM1 — runs iperf3 servers
SERVER_IP="192.168.1.4"   # VM2 — runs iperf3 clients + QoS
DURATION=30
BW="500M"
RESULT_DIR="results/egress_$(date +%Y%m%d_%H%M%S)"
BPF_OBJ="src/classifier.bpf.o"

PORT_EF=5201
PORT_AF=5202
PORT_BE=5203

EF_RATE=500
AF_RATE=300
BE_RATE=200

mkdir -p "$RESULT_DIR"

cleanup() {
    echo "[*] Cleaning up QoS on $IFACE..."
    sudo tc qdisc del dev $IFACE clsact 2>/dev/null || true
    sudo tc qdisc del dev $IFACE root 2>/dev/null || true
    # Kill local iperf3 clients
    pkill -f "iperf3 -c" 2>/dev/null || true
    sleep 2
}

setup_htb() {
    echo "[*] Setting up HTB on $IFACE (egress)..."
    sudo tc qdisc del dev $IFACE root 2>/dev/null || true

    sudo tc qdisc add dev $IFACE root handle 1: htb default 30
    sudo tc class add dev $IFACE parent 1: classid 1:1 \
        htb rate 1gbit ceil 1gbit
    sudo tc class add dev $IFACE parent 1:1 classid 1:10 \
        htb rate ${EF_RATE}mbit ceil ${EF_RATE}mbit prio 1
    sudo tc class add dev $IFACE parent 1:1 classid 1:20 \
        htb rate ${AF_RATE}mbit ceil ${AF_RATE}mbit prio 2
    sudo tc class add dev $IFACE parent 1:1 classid 1:30 \
        htb rate ${BE_RATE}mbit ceil ${BE_RATE}mbit prio 3

    sudo tc filter add dev $IFACE parent 1: protocol ip prio 1 \
        u32 match ip tos 0xb8 0xff flowid 1:10
    sudo tc filter add dev $IFACE parent 1: protocol ip prio 2 \
        u32 match ip tos 0x88 0xff flowid 1:20

    echo "[*] HTB: EF=${EF_RATE}M(ceil=${EF_RATE}M) AF=${AF_RATE}M BE=${BE_RATE}M"
    sudo tc -s class show dev $IFACE | head -20
}

setup_ebpf() {
    echo "[*] Setting up eBPF on $IFACE (egress)..."
    sudo tc qdisc del dev $IFACE clsact 2>/dev/null || true
    sudo tc qdisc del dev $IFACE root 2>/dev/null || true
    sudo tc qdisc add dev $IFACE clsact
    sudo tc filter add dev $IFACE egress bpf da obj $BPF_OBJ sec tc

    sleep 1
    local MAP_ID=$(sudo bpftool map show | grep "config_map" | head -1 | awk '{print $1}' | tr -d ':')
    if [ -n "$MAP_ID" ]; then
        for i in 0 1 2; do
            local RATE
            case $i in
                0) RATE=$EF_RATE ;;
                1) RATE=$AF_RATE ;;
                2) RATE=$BE_RATE ;;
            esac
            sudo bpftool map update id $MAP_ID \
                key $(printf '%02x 00 00 00' $i) \
                value $(python3 -c "
import struct
rate = $RATE * 1000000 // 8
burst = 4 * 1024 * 1024
d = struct.pack('<QQ', rate, burst)
print(' '.join(f'0x{b:02x}' for b in d))
") 2>/dev/null
        done
        echo "[*] eBPF rate configs: EF=${EF_RATE}M AF=${AF_RATE}M BE=${BE_RATE}M"
    else
        echo "[!] WARNING: config_map not found"
    fi
}

run_test() {
    local scenario=$1   # no_qos, htb, ebpf
    local proto=$2      # tcp, udp
    local label="${scenario}_${proto}"
    local u_flag=""
    [ "$proto" = "udp" ] && u_flag="-u"

    echo ""
    echo "  ┌─────────────────────────────────────────────────────────────┐"
    echo "  │  TEST: $label                                               "
    echo "  │  VM2 sends data → VM1 receives (egress test)                "
    echo "  └─────────────────────────────────────────────────────────────┘"
    echo ""
    echo "  [!] Make sure VM1 has iperf3 servers running:"
    echo "      iperf3 -s -p $PORT_EF &"
    echo "      iperf3 -s -p $PORT_AF &"
    echo "      iperf3 -s -p $PORT_BE &"
    echo ""

    read -p "  [?] Press ENTER when VM1 servers are ready... "

    # Start CPU monitoring
    mpstat -P ALL 1 $((DURATION + 10)) > "$RESULT_DIR/${label}_cpu.txt" 2>&1 &
    local mpstat_pid=$!

    echo "  [*] Starting 3 flows from VM2 → VM1 ($proto, ${BW} each, ${DURATION}s)..."

    # VM2 sends data OUT through egress → eBPF/HTB sees data packets
    iperf3 -c $CLIENT_IP -p $PORT_EF $u_flag -S 0xb8 -t $DURATION -b $BW -J \
        > "$RESULT_DIR/${label}_ef.json" 2>&1 &
    local pid_ef=$!

    iperf3 -c $CLIENT_IP -p $PORT_AF $u_flag -S 0x88 -t $DURATION -b $BW -J \
        > "$RESULT_DIR/${label}_af.json" 2>&1 &
    local pid_af=$!

    iperf3 -c $CLIENT_IP -p $PORT_BE $u_flag         -t $DURATION -b $BW -J \
        > "$RESULT_DIR/${label}_be.json" 2>&1 &
    local pid_be=$!

    echo "  [*] Flows started (PIDs: $pid_ef $pid_af $pid_be)"
    echo "  [*] Waiting ${DURATION}s..."

    # Progress + eBPF stats
    for i in $(seq 1 $DURATION); do
        sleep 1
        if [ $((i % 10)) -eq 0 ]; then
            echo "  [$i/${DURATION}s]"
            if [ "$scenario" = "ebpf" ]; then
                sudo bpftool map dump name stats_map 2>/dev/null | \
                    grep -E '"packets"|"dropped"' | head -6
            fi
            if [ "$scenario" = "htb" ]; then
                sudo tc -s class show dev $IFACE 2>/dev/null | grep -E "Sent|class" | head -6
            fi
        fi
    done

    # Wait for iperf3 to finish
    wait $pid_ef 2>/dev/null
    wait $pid_af 2>/dev/null
    wait $pid_be 2>/dev/null
    sleep 3

    kill $mpstat_pid 2>/dev/null || true

    # Save final stats
    if [ "$scenario" = "ebpf" ]; then
        sudo bpftool map dump name stats_map > "$RESULT_DIR/${label}_ebpf_stats.json" 2>/dev/null
    fi
    if [ "$scenario" = "htb" ]; then
        sudo tc -s class show dev $IFACE > "$RESULT_DIR/${label}_tc_stats.txt" 2>&1
    fi

    # Extract key metrics from JSON
    echo ""
    echo "  === Results: $label ==="
    for class in ef af be; do
        local file="$RESULT_DIR/${label}_${class}.json"
        if [ -f "$file" ]; then
            if [ "$proto" = "tcp" ]; then
                python3 -c "
import json, sys
try:
    d = json.load(open('$file'))
    e = d.get('end', {})
    ss = e.get('sum_sent', {})
    sr = e.get('sum_received', {})
    streams = e.get('streams', [{}])
    s0 = streams[0].get('sender', {}) if streams else {}
    print(f'  ${class^^}: sent={ss.get(\"bits_per_second\",0)/1e6:.1f}Mbps recv={sr.get(\"bits_per_second\",0)/1e6:.1f}Mbps retr={ss.get(\"retransmits\",\"?\")} rtt_mean={s0.get(\"mean_rtt\",\"?\")}μs')
except Exception as ex:
    print(f'  ${class^^}: error parsing — {ex}')
" 2>/dev/null
            else
                python3 -c "
import json, sys
try:
    d = json.load(open('$file'))
    e = d.get('end', {})
    ss = e.get('sum', {})
    print(f'  ${class^^}: sent={ss.get(\"bits_per_second\",0)/1e6:.1f}Mbps lost={ss.get(\"lost_packets\",\"?\")} loss={ss.get(\"lost_percent\",\"?\"):.1f}% jitter={ss.get(\"jitter_ms\",\"?\"):.3f}ms')
except Exception as ex:
    print(f'  ${class^^}: error — {ex}')
" 2>/dev/null
            fi
        fi
    done

    echo "  [*] Test '$label' complete"
    echo ""
}

# ===== Main =====
echo ""
echo "╔═════════════════════════════════════════════════════════════════════╗"
echo "║   Fair Egress Benchmark: No QoS vs HTB vs eBPF                    ║"
echo "║   All QoS at EGRESS — fair comparison                             ║"
echo "║   VM2 sends → VM1 receives                                        ║"
echo "║   Rate: EF=${EF_RATE}M  AF=${AF_RATE}M  BE=${BE_RATE}M  |  ${DURATION}s/test  |  6 tests     ║"
echo "║   Results: $RESULT_DIR"
echo "╚═════════════════════════════════════════════════════════════════════╝"
echo ""

# ============ TEST 1: No QoS — TCP ============
echo "━━━━ TEST 1/6: No QoS — TCP ━━━━"
cleanup
run_test "no_qos" "tcp"

# ============ TEST 2: No QoS — UDP ============
echo "━━━━ TEST 2/6: No QoS — UDP ━━━━"
cleanup
run_test "no_qos" "udp"

# ============ TEST 3: HTB — TCP ============
echo "━━━━ TEST 3/6: HTB — TCP ━━━━"
cleanup
setup_htb
run_test "htb" "tcp"

# ============ TEST 4: HTB — UDP ============
echo "━━━━ TEST 4/6: HTB — UDP ━━━━"
cleanup
setup_htb
run_test "htb" "udp"

# ============ TEST 5: eBPF — TCP ============
echo "━━━━ TEST 5/6: eBPF — TCP ━━━━"
cleanup
setup_ebpf
run_test "ebpf" "tcp"

# ============ TEST 6: eBPF — UDP ============
echo "━━━━ TEST 6/6: eBPF — UDP ━━━━"
cleanup
setup_ebpf
run_test "ebpf" "udp"

# ============ Done ============
cleanup

echo ""
echo "╔═════════════════════════════════════════════════════════════════════╗"
echo "║  All 6 tests complete!                                             ║"
echo "║  Results: $RESULT_DIR/                                 ║"
echo "║                                                                     ║"
echo "║  Files per test:                                                    ║"
echo "║    {scenario}_{proto}_ef.json  — EF iperf3 results                  ║"
echo "║    {scenario}_{proto}_af.json  — AF iperf3 results                  ║"
echo "║    {scenario}_{proto}_be.json  — BE iperf3 results                  ║"
echo "║    {scenario}_{proto}_cpu.txt  — CPU stats (mpstat)                 ║"
echo "╚═════════════════════════════════════════════════════════════════════╝"
