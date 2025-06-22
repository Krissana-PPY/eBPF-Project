#include "red_map.h" // include header สำหรับ map
#include <linux/bpf.h> // include header สำหรับ bpf
#include <linux/if_ether.h> // include header สำหรับ ethernet
#include <linux/ip.h> // include header สำหรับ ip
#include <bpf/bpf_helpers.h> // include helper functions ของ bpf

SEC("xdp") // ระบุ section สำหรับ XDP
int xdp_red_prog(struct xdp_md *ctx) {
    __u32 key = 0; // กำหนด key สำหรับ map
    __u32 *state = bpf_map_lookup_elem(&red_state_map, &key); // อ่านค่าระดับ RED จาก map
    if (!state) return XDP_PASS; // ถ้าอ่านไม่ได้ ให้ผ่าน packet

    if (*state == 0) { // ถ้าอยู่ในโซนสีเขียว
        return XDP_PASS; // อนุญาตให้ผ่าน
    } else if (*state == 1) { // ถ้าอยู่ในโซนสีเหลือง
        if ((bpf_get_prandom_u32() % 100) < 50) { // สุ่ม 50% ให้ drop
            return XDP_DROP; // ทิ้ง packet
        }
        return XDP_PASS; // อีก 50% ให้ผ่าน
    } else if (*state == 2) { // ถ้าอยู่ในโซนสีแดง
        return XDP_DROP; // ทิ้ง packet ทั้งหมด
    }

    return XDP_PASS; // กรณีอื่นๆ ให้ผ่าน
}

char LICENSE[] SEC("license") = "GPL"; // ระบุ license เป็น GPL
