// SPDX-License-Identifier: GPL-2.0
#include <linux/bpf.h>              // รวมฟังก์ชันและโครงสร้างข้อมูลสำหรับการใช้งาน BPF
#include <bpf/bpf_helpers.h>         // สำหรับช่วยในการสร้างโปรแกรม BPF
#include <linux/if_ether.h>          // สำหรับการจัดการ Ethernet header
#include <linux/ip.h>                // สำหรับการจัดการ IP header
#include "common.h"                  // รวมไฟล์ common.h ที่อาจจะมีโครงสร้างและฟังก์ชันที่ใช้ร่วมกัน

// สร้าง BPF map ชื่อ flow_map เพื่อเก็บข้อมูลของ flow โดยใช้ key เป็น IP address ของ source และ value เป็นข้อมูล flow_info
struct {
    __uint(type, BPF_MAP_TYPE_HASH);     // ประเภทของ map เป็น hash map
    __uint(max_entries, 256);             // จำนวน entry สูงสุดใน map
    __type(key, __u32);                   // key ของ map เป็นประเภท __u32 (IP address)
    __type(value, struct flow_info);     // value ของ map เป็นโครงสร้าง flow_info
} flow_map SEC(".maps");                 // กำหนด map นี้เป็น section ".maps"

// สร้าง BPF map ชื่อ events สำหรับการส่งข้อมูลไปยัง user space โดยใช้ perf event array
struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY); // ประเภทของ map เป็น perf_event_array
    __uint(key_size, sizeof(int));               // ขนาดของ key เป็นขนาดของ int (CPU ID)
    __uint(value_size, sizeof(__u32));           // ขนาดของ value เป็น __u32
    __uint(max_entries, 64);                     // จำนวน CPU ที่สามารถรองรับได้ หรือใช้ค่าจริงตามจำนวน CPU
} events SEC(".maps");                        // กำหนด map นี้เป็น section ".maps"

// SEC("xdp") ใช้เพื่อกำหนดโปรแกรมนี้ให้เป็น XDP program ที่จะถูกแนบกับ network interface
SEC("xdp")
int xdp_prog(struct xdp_md *ctx) {
    // กำหนดตัวแปร data_end และ data ที่ใช้ในการเข้าถึง packet data
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    // ตรวจสอบ Ethernet header
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)  // ตรวจสอบว่า Ethernet header ไม่เกินขอบเขตของ packet
        return XDP_ABORTED;  // ถ้าเกินขอบเขตให้ยกเลิกการประมวลผล

    // ตรวจสอบว่า packet เป็น IPv4 (Ethernet type = ETH_P_IP)
    if (eth->h_proto != __constant_htons(ETH_P_IP))
        return XDP_PASS;  // ถ้าไม่ใช่ IPv4 ก็ส่งผ่านไปยัง stack ปกติ

    // เข้าถึง IP header
    struct iphdr *iph = (void *)(eth + 1);
    if ((void *)(iph + 1) > data_end)  // ตรวจสอบว่า IP header ไม่เกินขอบเขตของ packet
        return XDP_ABORTED;  // ถ้าเกินขอบเขตให้ยกเลิกการประมวลผล

    // สร้าง flow_id โดยใช้ source IP address ของ packet
    __u32 flow_id = iph->saddr;
    // ใช้ bpf_ktime_get_ns เพื่อดึงเวลาปัจจุบันในรูปแบบ nano seconds
    __u64 time_bytes = bpf_ktime_get_ns();

    struct flow_info *flow;
    struct flow_info new_flow = {};   // สร้าง flow_info ใหม่สำหรับเก็บข้อมูล flow
    struct pkt_meta pkt = {};         // สร้าง pkt_meta สำหรับเก็บข้อมูล metadata ของ packet

    pkt.flow_id = flow_id;  // กำหนด flow ID
    pkt.len = data_end - data;  // กำหนดความยาวของ packet
    pkt.timestamp = time_bytes;  // กำหนด timestamp ของ packet

    // ค้นหา flow ที่มี flow_id ตรงกับที่พบใน map flow_map
    flow = bpf_map_lookup_elem(&flow_map, &flow_id);
    if (flow) {
        // ถ้ามี flow ที่พบ ให้กำหนด priority ใหม่โดยใช้เวลาที่มากที่สุดระหว่างเวลาที่เก็บไว้ใน flow และเวลาปัจจุบัน
        pkt.priority = time_bytes > flow->end_bytes ? time_bytes : flow->end_bytes;
        // อัพเดทค่า end_bytes ของ flow ใน map
        flow->end_bytes = pkt.len;
    } else {
        // ถ้าไม่พบ flow ให้สร้าง flow ใหม่
        new_flow.end_bytes = pkt.len;
        pkt.priority = time_bytes;
        // อัพเดท map โดยเพิ่ม flow ใหม่ลงไป
        bpf_map_update_elem(&flow_map, &flow_id, &new_flow, BPF_ANY);
    }

    // ส่งข้อมูล packet metadata ไปยัง user space ผ่าน perf event
    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &pkt, sizeof(pkt));

    // DROP packet หลังจากประมวลผลเสร็จแล้ว
    return XDP_DROP;
}

// กำหนดลิขสิทธิ์ของโปรแกรมเป็น GPL
char LICENSE[] SEC("license") = "GPL";