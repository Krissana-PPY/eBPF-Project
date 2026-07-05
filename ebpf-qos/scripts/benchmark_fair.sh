#!/bin/bash
# scripts/benchmark_fair.sh
# Fair QoS Benchmark under 1 Gbps congestion
#
# Scenario: Link capacity = 1 Gbps, Total traffic = 1.5 Gbps (oversubscribed)
# Target: EF=500M (50%), AF=300M (30%), BE=200M (20%)
#
# All 3 methods limited to same total 1 Gbps — fair comparison
#   No QoS: TBF 1Gbps (equal sharing, no priority)
#   HTB:    Parent 1Gbps, classes 500/300/200
#   eBPF:   Rate 500/300/200, ceil same (strict)
#
# VM2 sends → VM1 receives (egress test)
# Run on VM2: sudo bash scripts/benchmark_fair.sh

set -e

IFACE="ens19"
CLIENT_IP="192.168.1.3"
DURATION=30
BW="500M"
TOTAL_BW="1gbit"
RESULT_DIR="results/fair_$(date +%Y%m%d_%H%M%S)"
BPF_OBJ="src/classifier.bpf.o"

PORT_EF=5201
PORT_AF=5202
PORT_BE=5203

EF_RATE=500
AF_RATE=300
BE_RATE=200

mkdir -p "$RESULT_DIR"

cleanup() {
    sudo tc qdisc del dev $IFACE clsact 2>/dev/null || true
    sudo tc qdisc del dev $IFACE root 2>/dev/null || true
    sudo tc qdisc replace dev $IFACE root fq_codel 2>/dev/null || true
    pkill -f "iperf3 -c" 2>/dev/null || true
    sleep 2
}

setup_no_qos() {
    echo "[*] No QoS: TBF rate limiter at $TOTAL_BW (no per-class rules)"
    sudo tc qdisc del dev $IFACE root 2>/dev/null || true
    sudo tc qdisc add dev $IFACE root tbf rate $TOTAL_BW burst 256kb latency 10ms
    echo "[*] All 3 flows share $TOTAL_BW equally — no priority"
    sudo tc qdisc show dev $IFACE
}

setup_htb() {
    echo "[*] HTB: Parent $TOTAL_BW → EF=${EF_RATE}M AF=${AF_RATE}M BE=${BE_RATE}M"
    sudo tc qdisc del dev $IFACE root 2>/dev/null || true

    sudo tc qdisc add dev $IFACE root handle 1: htb default 30
    sudo tc class add dev $IFACE parent 1: classid 1:1 \
        htb rate $TOTAL_BW ceil $TOTAL_BW
    sudo tc class add dev $IFACE parent 1:1 classid 1:10 \
        htb rate ${EF_RATE}mbit ceil ${EF_RATE}mbit prio 1
    sudo tc class add dev $IFACE parent 1:1 classid 1:20 \
        htb rate ${AF_RATE}mbit ceil ${AF_RATE}mbit prio 2
    sudo tc class add dev $IFACE parent 1:1 classid 1:30 \
        htb rate ${BE_RATE}mbit ceil ${BE_RATE}mbit prio 3

    # FIX: mask 0xfc ignores ECN bits (lowest 2 bits)
    # Without this, ECN-enabled TCP changes TOS 0xb8→0xba and filter fails!
    sudo tc filter add dev $IFACE parent 1: protocol ip prio 1 \
        u32 match ip tos 0xb8 0xfc flowid 1:10
    sudo tc filter add dev $IFACE parent 1: protocol ip prio 2 \
        u32 match ip tos 0x88 0xfc flowid 1:20

    sudo tc qdisc show dev $IFACE
}

setup_ebpf() {
    echo "[*] eBPF: FQ root + clsact + shaping EF=${EF_RATE}M AF=${AF_RATE}M BE=${BE_RATE}M"
    sudo tc qdisc del dev $IFACE clsact 2>/dev/null || true
    sudo tc qdisc del dev $IFACE root 2>/dev/null || true

    sudo tc qdisc add dev $IFACE root fq
    sudo tc qdisc add dev $IFACE clsact
    sudo tc filter add dev $IFACE egress bpf da obj $BPF_OBJ sec tc

    sleep 1
    local MAP_ID=$(sudo bpftool map show | grep "config_map" | head -1 | awk '{print $1}' | tr -d ':')
    if [ -n "$MAP_ID" ]; then
        for i in 0 1 2; do
            local RATE CEIL
            case $i in
                0) RATE=$EF_RATE; CEIL=$EF_RATE ;;   # EF: 500/500 (passthrough anyway)
                1) RATE=$AF_RATE; CEIL=500 ;;         # AF: 300/500 (borrowing zone)
                2) RATE=$BE_RATE; CEIL=300 ;;          # BE: 200/300 (borrowing zone)
            esac
            sudo bpftool map update id $MAP_ID \
                key $(printf '%02x 00 00 00' $i) \
                value $(python3 -c "
import struct
rate = $RATE * 1000000 // 8
ceil = $CEIL * 1000000 // 8
d = struct.pack('<QQ', rate, ceil)
print(' '.join(f'0x{b:02x}' for b in d))
") 2>/dev/null
        done
        echo "[*] eBPF configs: rate=ceil (strict, no borrowing)"
    fi
    sudo tc qdisc show dev $IFACE
}

run_test() {
    local scenario=$1
    local proto=$2
    local label="${scenario}_${proto}"
    local u_flag=""
    [ "$proto" = "udp" ] && u_flag="-u"

    echo ""
    echo "  ┌──────────────────────────────────────────────────────────────┐"
    echo "  │  $label  |  Link: 1 Gbps  |  Traffic: 3×500M = 1.5 Gbps    │"
    echo "  │  Target: EF=500M (50%) AF=300M (30%) BE=200M (20%)          │"
    echo "  └──────────────────────────────────────────────────────────────┘"

    read -p "  [?] Confirm VM1 servers are running, press ENTER... "

    mpstat -P ALL 1 $((DURATION + 10)) > "$RESULT_DIR/${label}_cpu.txt" 2>&1 &
    local mpstat_pid=$!

    echo "  [*] Sending 3 flows ($proto)..."

    iperf3 -c $CLIENT_IP -p $PORT_EF $u_flag -S 0xb8 -t $DURATION -b $BW -J \
        > "$RESULT_DIR/${label}_ef.json" 2>&1 &
    local pid_ef=$!

    iperf3 -c $CLIENT_IP -p $PORT_AF $u_flag -S 0x88 -t $DURATION -b $BW -J \
        > "$RESULT_DIR/${label}_af.json" 2>&1 &
    local pid_af=$!

    iperf3 -c $CLIENT_IP -p $PORT_BE $u_flag         -t $DURATION -b $BW -J \
        > "$RESULT_DIR/${label}_be.json" 2>&1 &
    local pid_be=$!

    for i in $(seq 1 $DURATION); do
        sleep 1
        [ $((i % 10)) -eq 0 ] && echo "  [$i/${DURATION}s]"
    done

    wait $pid_ef 2>/dev/null; wait $pid_af 2>/dev/null; wait $pid_be 2>/dev/null
    sleep 3
    kill $mpstat_pid 2>/dev/null || true

    if [ "$scenario" = "ebpf" ]; then
        sudo bpftool map dump name stats_map > "$RESULT_DIR/${label}_ebpf_stats.json" 2>/dev/null
    fi
    if [ "$scenario" = "htb" ]; then
        sudo tc -s class show dev $IFACE > "$RESULT_DIR/${label}_tc_stats.txt" 2>&1
    fi

    echo "  === Results: $label ==="
    for class in ef af be; do
        local file="$RESULT_DIR/${label}_${class}.json"
        [ ! -f "$file" ] && continue
        if [ "$proto" = "tcp" ]; then
            python3 -c "
import json
try:
    d=json.load(open('$file'))
    e=d.get('end',{})
    ss=e.get('sum_sent',{})
    sr=e.get('sum_received',{})
    st=e.get('streams',[{}])
    s0=st[0].get('sender',{}) if st else {}
    print(f'  ${class^^}: recv={sr.get(\"bits_per_second\",0)/1e6:.1f}Mbps retr={ss.get(\"retransmits\",\"?\")} rtt={s0.get(\"mean_rtt\",\"?\")}us')
except: print('  ${class^^}: parse error')
" 2>/dev/null
        else
            python3 -c "
import json
try:
    d=json.load(open('$file'))
    e=d.get('end',{})
    ss=e.get('sum',{})
    print(f'  ${class^^}: recv={ss.get(\"bits_per_second\",0)/1e6:.1f}Mbps loss={ss.get(\"lost_percent\",0):.1f}% jitter={ss.get(\"jitter_ms\",0):.3f}ms')
except: print('  ${class^^}: parse error')
" 2>/dev/null
        fi
    done
    echo ""
}

# ===== Main =====
echo ""
echo "╔═══════════════════════════════════════════════════════════════════════╗"
echo "║   Fair QoS Benchmark: 1 Gbps Link × 1.5 Gbps Traffic              ║"
echo "║   Target: EF=500M (50%)  AF=300M (30%)  BE=200M (20%)             ║"
echo "║   All scenarios: same 1 Gbps total — fair comparison               ║"
echo "║   Tests: 6 (3 scenarios × TCP + UDP)                              ║"
echo "║   Results: $RESULT_DIR"
echo "╚═══════════════════════════════════════════════════════════════════════╝"

# Enable ECN for TCP
echo "[*] Enabling ECN..."
sudo sysctl -w net.ipv4.tcp_ecn=1
echo "[!] Make sure VM1 also has: sudo sysctl -w net.ipv4.tcp_ecn=1"
echo ""

# No QoS — TCP
echo ""; echo "━━━━ TEST 1/6: No QoS (TBF 1G) — TCP ━━━━"
cleanup; setup_no_qos; run_test "no_qos" "tcp"

# No QoS — UDP
echo "━━━━ TEST 2/6: No QoS (TBF 1G) — UDP ━━━━"
cleanup; setup_no_qos; run_test "no_qos" "udp"

# HTB — TCP
echo "━━━━ TEST 3/6: HTB (500/300/200) — TCP ━━━━"
cleanup; setup_htb; run_test "htb" "tcp"

# HTB — UDP
echo "━━━━ TEST 4/6: HTB (500/300/200) — UDP ━━━━"
cleanup; setup_htb; run_test "htb" "udp"

# eBPF — TCP
echo "━━━━ TEST 5/6: eBPF Shaping (500/300/200) — TCP ━━━━"
cleanup; setup_ebpf; run_test "ebpf" "tcp"

# eBPF — UDP
echo "━━━━ TEST 6/6: eBPF Shaping (500/300/200) — UDP ━━━━"
cleanup; setup_ebpf; run_test "ebpf" "udp"

cleanup

echo "╔═══════════════════════════════════════════════════════════════════════╗"
echo "║  All 6 tests complete!                                              ║"
echo "║  Results: $RESULT_DIR/                                              ║"
echo "╚═══════════════════════════════════════════════════════════════════════╝"
