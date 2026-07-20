#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
QoS Research Results Summarizer
ใช้สรุปผลการทดสอบเปรียบเทียบ No QoS, HTB, และ eBPF
"""

import json
import os
import re
import sys
from pathlib import Path
from statistics import mean, stdev

# Windows: ให้ stdout รองรับ UTF-8
if sys.platform == "win32":
    import io
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")

RESULTS_DIR = Path(__file__).parent / "ผลวิจัย"

# ชื่อ class traffic และความหมาย
TRAFFIC_CLASSES = {
    "ef": "EF (Expedited Forwarding) - สูงสุด",
    "af": "AF (Assured Forwarding)   - กลาง",
    "be": "BE (Best Effort)          - ต่ำสุด",
}

EBPF_CLASS_NAMES = {0: "EF", 1: "AF", 2: "BE"}

QOS_TYPES = ["no_qos", "htb", "ebpf"]
QOS_LABELS = {"no_qos": "No QoS", "htb": "HTB", "ebpf": "eBPF"}


# ─── Parser functions ───────────────────────────────────────────────────────

def parse_iperf_json(path: Path) -> dict:
    """อ่าน iperf3 JSON แล้วคืน summary stats"""
    with open(path, encoding="utf-8") as f:
        data = json.load(f)

    end = data.get("end", {})
    sum_sent = end.get("sum_sent", {})
    sum_recv = end.get("sum_received", {})
    cpu = end.get("cpu_utilization_percent", {})

    intervals = data.get("intervals", [])
    rtts = [
        s["rtt"]
        for iv in intervals
        for s in iv.get("streams", [])
        if "rtt" in s
    ]
    bps_list = [
        iv["sum"]["bits_per_second"]
        for iv in intervals
        if "sum" in iv
    ]
    retx_list = [
        iv["sum"].get("retransmits", 0)
        for iv in intervals
        if "sum" in iv
    ]

    return {
        "throughput_mbps": sum_sent.get("bits_per_second", 0) / 1e6,
        "bytes_sent": sum_sent.get("bytes", 0),
        "retransmits": sum_sent.get("retransmits", 0),
        "duration_s": sum_sent.get("seconds", 0),
        "avg_rtt_us": mean(rtts) if rtts else 0,
        "max_rtt_us": max(rtts) if rtts else 0,
        "min_rtt_us": min(rtts) if rtts else 0,
        "rtt_std_us": stdev(rtts) if len(rtts) > 1 else 0,
        "throughput_std_mbps": stdev(b / 1e6 for b in bps_list) if len(bps_list) > 1 else 0,
        "total_retransmits_intervals": sum(retx_list),
        "cpu_host_total": cpu.get("host_total", 0),
        "cpu_host_user": cpu.get("host_user", 0),
        "cpu_host_system": cpu.get("host_system", 0),
        "cpu_remote_total": cpu.get("remote_total", 0),
    }


def parse_cpu_txt(path: Path) -> dict:
    """อ่านไฟล์ sar CPU stats แล้วคืนค่าเฉลี่ย"""
    lines = path.read_text(encoding="utf-8").splitlines()
    usr_vals, sys_vals, soft_vals, idle_vals = [], [], [], []

    for line in lines:
        parts = line.split()
        if len(parts) >= 11 and parts[1] == "all":
            try:
                usr_vals.append(float(parts[2]))
                sys_vals.append(float(parts[4]))
                soft_vals.append(float(parts[6]))
                idle_vals.append(float(parts[10]))
            except ValueError:
                pass

    return {
        "avg_usr": mean(usr_vals) if usr_vals else 0,
        "avg_sys": mean(sys_vals) if sys_vals else 0,
        "avg_soft": mean(soft_vals) if soft_vals else 0,
        "avg_idle": mean(idle_vals) if idle_vals else 0,
        "avg_total": mean(u + s + sf for u, s, sf in zip(usr_vals, sys_vals, soft_vals)) if usr_vals else 0,
        "samples": len(usr_vals),
    }


def parse_htb_tc_stats(path: Path) -> dict:
    """อ่าน tc stats ของ HTB แล้วแยก class"""
    text = path.read_text(encoding="utf-8")
    classes = {}

    # จับ block ของแต่ละ class
    blocks = re.split(r"\n(?=class htb)", text.strip())
    for block in blocks:
        rate_match = re.search(r"class htb (\S+).*?rate (\S+)", block)
        sent_match = re.search(r"Sent (\d+) bytes (\d+) pkt \(dropped (\d+), overlimits (\d+)", block)
        if rate_match and sent_match:
            cls_id = rate_match.group(1)
            rate = rate_match.group(2)
            bytes_sent = int(sent_match.group(1))
            pkts = int(sent_match.group(2))
            dropped = int(sent_match.group(3))
            overlimits = int(sent_match.group(4))
            classes[cls_id] = {
                "rate": rate,
                "bytes_sent": bytes_sent,
                "packets": pkts,
                "dropped": dropped,
                "overlimits": overlimits,
                "throughput_mbps": bytes_sent * 8 / 30 / 1e6,
            }
    return classes


def parse_ebpf_stats(path: Path) -> dict:
    """อ่าน eBPF map stats"""
    with open(path, encoding="utf-8") as f:
        data = json.load(f)

    result = {}
    for entry in data:
        key = entry["key"]
        val = entry["value"]
        class_name = EBPF_CLASS_NAMES.get(key, f"class_{key}")
        result[class_name] = {
            "packets": val.get("packets", 0),
            "bytes": val.get("bytes", 0),
            "borrowed": val.get("borrowed", 0),
            "ecn_marked": val.get("ecn_marked", 0),
            "delayed": val.get("delayed", 0),
            "throughput_mbps": val.get("bytes", 0) * 8 / 30 / 1e6,
        }
    return result


# ─── Loader ─────────────────────────────────────────────────────────────────

def load_all_results() -> dict:
    """โหลดไฟล์ผลลัพธ์ทั้งหมดในโฟลเดอร์ผลวิจัย"""
    results = {}
    files = list(RESULTS_DIR.glob("*"))

    for path in files:
        name = path.stem
        # ตัดตัวเลขท้ายชื่อออก เช่น " (2)"
        name = re.sub(r"\s*\(\d+\)\s*$", "", name).strip()

        # ตรวจ qos type จากชื่อไฟล์ (ลำดับยาวก่อน เช่น no_qos ก่อน no)
        qos = None
        for q in sorted(QOS_TYPES, key=len, reverse=True):
            if name.startswith(q + "_"):
                qos = q
                break
        if qos is None:
            continue

        if path.suffix == ".json":
            # eBPF stats map
            if "ebpf_stats" in name:
                key = f"{qos}_ebpf_stats"
                try:
                    results[key] = parse_ebpf_stats(path)
                except Exception as e:
                    print(f"  [!] ข้ามไฟล์ {path.name}: {e}")
            else:
                # iperf3 JSON — traffic class อยู่ท้ายชื่อ
                traffic_class = name.split("_")[-1]
                key = f"{qos}_{traffic_class}"
                try:
                    results[key] = parse_iperf_json(path)
                except Exception as e:
                    print(f"  [!] ข้ามไฟล์ {path.name}: {e}")

        elif path.suffix == ".txt":
            if "cpu" in name:
                key = f"{qos}_cpu"
                try:
                    results[key] = parse_cpu_txt(path)
                except Exception as e:
                    print(f"  [!] ข้ามไฟล์ {path.name}: {e}")
            elif "tc_stats" in name:
                key = f"{qos}_tc_stats"
                try:
                    results[key] = parse_htb_tc_stats(path)
                except Exception as e:
                    print(f"  [!] ข้ามไฟล์ {path.name}: {e}")

    return results


# ─── Display helpers ─────────────────────────────────────────────────────────

def sep(char="-", width=80):
    print(char * width)


def header(title: str):
    sep("=")
    print(f"  {title}")
    sep("=")


def section(title: str):
    print()
    sep()
    print(f"  {title}")
    sep()


def fmt_mbps(v: float) -> str:
    return f"{v:8.2f} Mbps"


def fmt_rtt(v: float) -> str:
    return f"{v:7.0f} µs"


def fmt_pct(v: float) -> str:
    return f"{v:6.1f}%"


# ─── Report sections ─────────────────────────────────────────────────────────

def report_throughput(results: dict):
    section("1. Throughput เฉลี่ยแยกตาม Traffic Class (Mbps)")
    print(f"  {'Traffic Class':<38} {'No QoS':>12} {'HTB':>12} {'eBPF':>12}")
    sep("-")

    for tc_key, tc_label in TRAFFIC_CLASSES.items():
        vals = {}
        for qos in QOS_TYPES:
            key = f"{qos}_{tc_key}"
            vals[qos] = results[key]["throughput_mbps"] if key in results else None

        no_qos = f"{vals['no_qos']:8.2f}" if vals["no_qos"] is not None else "    N/A "
        htb    = f"{vals['htb']:8.2f}"    if vals["htb"]    is not None else "    N/A "
        ebpf   = f"{vals['ebpf']:8.2f}"   if vals["ebpf"]   is not None else "    N/A "
        print(f"  {tc_label:<38} {no_qos:>12} {htb:>12} {ebpf:>12}")

    # แสดง throughput ทั้งหมดรวม
    print()
    print("  หมายเหตุ: Target rate EF=500 Mbps, AF=300 Mbps, BE=200 Mbps (HTB/eBPF)")


def report_rtt(results: dict):
    section("2. RTT (Round-Trip Time) แยกตาม Traffic Class")
    print(f"  {'Traffic Class':<38} {'No QoS (avg)':>14} {'HTB (avg)':>14} {'eBPF (avg)':>14}")
    sep("-")

    for tc_key, tc_label in TRAFFIC_CLASSES.items():
        vals = {}
        for qos in QOS_TYPES:
            key = f"{qos}_{tc_key}"
            vals[qos] = results[key]["avg_rtt_us"] if key in results else None

        no_qos = f"{vals['no_qos']:7.0f} µs" if vals["no_qos"] is not None else "    N/A   "
        htb    = f"{vals['htb']:7.0f} µs"    if vals["htb"]    is not None else "    N/A   "
        ebpf   = f"{vals['ebpf']:7.0f} µs"   if vals["ebpf"]   is not None else "    N/A   "
        print(f"  {tc_label:<38} {no_qos:>14} {htb:>14} {ebpf:>14}")

    print()
    print(f"  {'Traffic Class':<38} {'No QoS (max)':>14} {'HTB (max)':>14} {'eBPF (max)':>14}")
    sep("-")
    for tc_key, tc_label in TRAFFIC_CLASSES.items():
        vals = {}
        for qos in QOS_TYPES:
            key = f"{qos}_{tc_key}"
            vals[qos] = results[key]["max_rtt_us"] if key in results else None

        no_qos = f"{vals['no_qos']:7.0f} µs" if vals["no_qos"] is not None else "    N/A   "
        htb    = f"{vals['htb']:7.0f} µs"    if vals["htb"]    is not None else "    N/A   "
        ebpf   = f"{vals['ebpf']:7.0f} µs"   if vals["ebpf"]   is not None else "    N/A   "
        print(f"  {tc_label:<38} {no_qos:>14} {htb:>14} {ebpf:>14}")


def report_retransmits(results: dict):
    section("3. TCP Retransmits (จำนวนครั้งที่ส่งซ้ำ — ต่ำ = ดี)")
    print(f"  {'Traffic Class':<38} {'No QoS':>10} {'HTB':>10} {'eBPF':>10}")
    sep("-")

    for tc_key, tc_label in TRAFFIC_CLASSES.items():
        vals = {}
        for qos in QOS_TYPES:
            key = f"{qos}_{tc_key}"
            vals[qos] = results[key]["retransmits"] if key in results else None

        no_qos = f"{vals['no_qos']:6.0f}" if vals["no_qos"] is not None else "   N/A"
        htb    = f"{vals['htb']:6.0f}"    if vals["htb"]    is not None else "   N/A"
        ebpf   = f"{vals['ebpf']:6.0f}"   if vals["ebpf"]   is not None else "   N/A"
        print(f"  {tc_label:<38} {no_qos:>10} {htb:>10} {ebpf:>10}")


def report_cpu(results: dict):
    section("4. CPU Utilization (จาก sar — ฝั่ง sender)")
    print(f"  {'Metric':<20} {'No QoS':>12} {'HTB':>12} {'eBPF':>12}")
    sep("-")

    for metric, label in [
        ("avg_usr",   "%usr (user space)"),
        ("avg_sys",   "%sys (kernel)    "),
        ("avg_soft",  "%soft (softirq)  "),
        ("avg_idle",  "%idle            "),
        ("avg_total", "%total (usr+sys+soft)"),
    ]:
        vals = {}
        for qos in QOS_TYPES:
            key = f"{qos}_cpu"
            vals[qos] = results[key][metric] if key in results else None

        no_qos = f"{vals['no_qos']:6.1f}%" if vals["no_qos"] is not None else "   N/A "
        htb    = f"{vals['htb']:6.1f}%"    if vals["htb"]    is not None else "   N/A "
        ebpf   = f"{vals['ebpf']:6.1f}%"   if vals["ebpf"]   is not None else "   N/A "
        print(f"  {label:<20} {no_qos:>12} {htb:>12} {ebpf:>12}")

    # CPU จาก iperf end stats ด้วย
    print()
    print("  CPU จาก iperf3 end stats (ฝั่ง sender):")
    print(f"  {'Traffic Class':<38} {'No QoS':>12} {'HTB':>12} {'eBPF':>12}")
    sep("-")
    for tc_key, tc_label in TRAFFIC_CLASSES.items():
        vals = {}
        for qos in QOS_TYPES:
            key = f"{qos}_{tc_key}"
            vals[qos] = results[key]["cpu_host_total"] if key in results else None

        no_qos = f"{vals['no_qos']:6.1f}%" if vals["no_qos"] is not None else "   N/A "
        htb    = f"{vals['htb']:6.1f}%"    if vals["htb"]    is not None else "   N/A "
        ebpf   = f"{vals['ebpf']:6.1f}%"   if vals["ebpf"]   is not None else "   N/A "
        print(f"  {tc_label:<38} {no_qos:>12} {htb:>12} {ebpf:>12}")


def report_htb_tc(results: dict):
    if "htb_tc_stats" not in results:
        return
    section("5. HTB TC Statistics (รายละเอียด class)")
    tc = results["htb_tc_stats"]
    print(f"  {'Class ID':<10} {'Rate':>10} {'Bytes Sent':>16} {'Pkts':>10} {'Dropped':>10} {'Overlimits':>12}")
    sep("-")
    for cls_id, stats in sorted(tc.items()):
        print(
            f"  {cls_id:<10} {stats['rate']:>10} "
            f"{stats['bytes_sent']:>16,} {stats['packets']:>10,} "
            f"{stats['dropped']:>10,} {stats['overlimits']:>12,}"
        )
    print()
    print("  Throughput ต่อ class (คำนวณจาก bytes/30s):")
    for cls_id, stats in sorted(tc.items()):
        print(f"    {cls_id}: {stats['throughput_mbps']:.2f} Mbps")


def report_ebpf_stats(results: dict):
    if "ebpf_ebpf_stats" not in results:
        return
    section("6. eBPF Map Statistics (รายละเอียด class)")
    ebpf = results["ebpf_ebpf_stats"]
    print(f"  {'Class':<8} {'Packets':>10} {'Bytes':>16} {'Borrowed':>10} {'ECN Marked':>12} {'Delayed':>10} {'Mbps':>10}")
    sep("-")
    for cls_name, stats in sorted(ebpf.items()):
        print(
            f"  {cls_name:<8} {stats['packets']:>10,} {stats['bytes']:>16,} "
            f"{stats['borrowed']:>10,} {stats['ecn_marked']:>12,} "
            f"{stats['delayed']:>10,} {stats['throughput_mbps']:>10.2f}"
        )


def report_comparison_summary(results: dict):
    section("7. สรุปเปรียบเทียบ QoS — ข้อสังเกตสำคัญ")

    observations = []

    # EF throughput accuracy
    for qos in ["htb", "ebpf"]:
        key = f"{qos}_ef"
        if key in results:
            tp = results[key]["throughput_mbps"]
            diff = abs(tp - 500)
            pct = diff / 500 * 100
            observations.append(
                f"  [{QOS_LABELS[qos]}] EF throughput: {tp:.2f} Mbps "
                f"(ต่างจาก target 500 Mbps = {pct:.2f}%)"
            )

    # RTT comparison EF
    rtt_vals = {}
    for qos in QOS_TYPES:
        key = f"{qos}_ef"
        if key in results:
            rtt_vals[qos] = results[key]["avg_rtt_us"]

    if rtt_vals:
        best_qos = min(rtt_vals, key=rtt_vals.get)
        observations.append(
            f"  RTT ต่ำสุดใน EF: {QOS_LABELS[best_qos]} "
            f"({rtt_vals[best_qos]:.0f} µs)"
        )

    # CPU comparison
    cpu_keys = [f"{qos}_cpu" for qos in QOS_TYPES if f"{qos}_cpu" in results]
    if cpu_keys:
        cpu_total = {
            qos: results[f"{qos}_cpu"]["avg_total"]
            for qos in QOS_TYPES
            if f"{qos}_cpu" in results
        }
        if cpu_total:
            best_cpu = min(cpu_total, key=cpu_total.get)
            observations.append(
                f"  CPU overhead ต่ำสุด: {QOS_LABELS[best_cpu]} "
                f"(avg {cpu_total[best_cpu]:.1f}% total)"
            )

    # eBPF ECN/delayed stats
    if "ebpf_ebpf_stats" in results:
        ebpf_stats = results["ebpf_ebpf_stats"]
        total_ecn = sum(s["ecn_marked"] for s in ebpf_stats.values())
        total_delayed = sum(s["delayed"] for s in ebpf_stats.values())
        total_borrowed = sum(s["borrowed"] for s in ebpf_stats.values())
        observations.append(
            f"  [eBPF] ECN marked: {total_ecn:,} packets, "
            f"delayed: {total_delayed:,}, borrowed: {total_borrowed:,}"
        )

    for obs in observations:
        print(obs)

    print()
    print("  ตารางสรุป QoS Fairness (EF vs AF vs BE throughput ratio):")
    print(f"  {'QoS Type':<10} {'EF (Mbps)':>12} {'AF (Mbps)':>12} {'BE (Mbps)':>12} {'EF:AF:BE ratio'}")
    sep("-")
    for qos in QOS_TYPES:
        ef = results.get(f"{qos}_ef", {}).get("throughput_mbps")
        af = results.get(f"{qos}_af", {}).get("throughput_mbps")
        be = results.get(f"{qos}_be", {}).get("throughput_mbps")
        if all(v is not None for v in [ef, af, be]) and be > 0:
            ratio_ef = ef / be
            ratio_af = af / be
            ratio_str = f"{ratio_ef:.1f} : {ratio_af:.1f} : 1.0"
        else:
            ratio_str = "N/A"
        ef_str = f"{ef:.2f}" if ef is not None else " N/A "
        af_str = f"{af:.2f}" if af is not None else " N/A "
        be_str = f"{be:.2f}" if be is not None else " N/A "
        print(f"  {QOS_LABELS[qos]:<10} {ef_str:>12} {af_str:>12} {be_str:>12}   {ratio_str}")


# ─── Main ─────────────────────────────────────────────────────────────────────

def main():
    header("eBPF QoS Research — สรุปผลการทดสอบ")
    print(f"  โฟลเดอร์ผลลัพธ์: {RESULTS_DIR}")
    print()

    if not RESULTS_DIR.exists():
        print(f"  [ERROR] ไม่พบโฟลเดอร์ {RESULTS_DIR}")
        sys.exit(1)

    print("  กำลังโหลดไฟล์ผลลัพธ์...")
    results = load_all_results()

    print(f"  โหลดสำเร็จ {len(results)} ชุดข้อมูล:")
    for k in sorted(results.keys()):
        print(f"    • {k}")

    report_throughput(results)
    report_rtt(results)
    report_retransmits(results)
    report_cpu(results)
    report_htb_tc(results)
    report_ebpf_stats(results)
    report_comparison_summary(results)

    sep("=")
    print("  เสร็จสิ้น — วางไฟล์ผลลัพธ์ใหม่ในโฟลเดอร์ 'ผลวิจัย' แล้วรันอีกครั้งได้เลย")
    sep("=")


if __name__ == "__main__":
    main()
