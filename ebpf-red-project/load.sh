#!/bin/bash
set -e  # ถ้ามี error ให้หยุด script ทันที

IFACE=eth0  # กำหนดชื่อ network interface

echo "[+] Cleaning up old qdisc and XDP..."  # แจ้งเตือนการลบ qdisc และ XDP เก่า
tc qdisc del dev $IFACE clsact 2>/dev/null || true  # ลบ qdisc เดิม ถ้ามี
ip link set dev $IFACE xdp off 2>/dev/null || true  # ปิด XDP เดิม ถ้ามี

echo "[+] Loading XDP program..."  # แจ้งเตือนการโหลด XDP
ip link set dev $IFACE xdp obj xdp_red_prog.o sec xdp  # โหลด XDP object เข้า interface

echo "[+] Loading kprobe program..."  # แจ้งเตือนการโหลด kprobe
bpftool prog loadall kprobe_qdisc.o /sys/fs/bpf/myprog  # โหลด kprobe object ไปยัง bpffs
bpftool prog attach pinned /sys/fs/bpf/myprog/kprobe__sch_direct_xmit \
    type kprobe \
    name kprobe__sch_direct_xmit  # ผูกโปรแกรม kprobe กับ function sch_direct_xmit

echo "[+] Creating map pinning (if not exist)..."  # แจ้งเตือนการ pin map
bpftool map pin name red_state_map /sys/fs/bpf/red_state_map 2>/dev/null || true  # pin red_state_map
bpftool map pin name max_qlen_map /sys/fs/bpf/max_qlen_map 2>/dev/null || true  # pin max_qlen_map

echo "[+] Reading qdisc limit..."  # แจ้งเตือนการอ่านค่า limit ของ qdisc
LIMIT=$(tc -s qdisc show dev $IFACE | grep -o 'limit [0-9]\+' | awk '{print $2}' | head -1)  # อ่านค่า limit

if [ -z "$LIMIT" ]; then  # ถ้าไม่ได้ค่า limit
  echo "[!] Could not detect qdisc limit, using default 1000"  # แจ้งเตือนและใช้ค่า default
  LIMIT=1000
else
  echo "[+] Detected qdisc limit: $LIMIT"  # แสดงค่า limit ที่ตรวจพบ
fi

echo "[+] Updating max_qlen map..."  # แจ้งเตือนการอัพเดท map
bpftool map update pinned /sys/fs/bpf/max_qlen_map key 0 value $LIMIT  # อัพเดทค่า max_qlen ใน map

echo "[+] Load complete."  # แจ้งเตือนเสร็จสิ้น
