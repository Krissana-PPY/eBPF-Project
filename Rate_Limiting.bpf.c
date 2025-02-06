// รวมไฟล์เฮดเดอร์ที่จำเป็นสำหรับ eBPF
#include <linux/bpf.h>          // ฟังก์ชันหลักของ eBPF
#include <linux/if_ether.h>     // โครงสร้างของ Ethernet header
#include <linux/ip.h>           // โครงสร้างของ IP header
#include <bpf/bpf_helpers.h>    // Helper function ของ eBPF

// กำหนดค่าจำนวนแพ็กเก็ตสูงสุดที่แต่ละ IP สามารถส่งได้
#define MAX_PACKETS 10

// สร้าง BPF map สำหรับเก็บจำนวนแพ็กเก็ตของแต่ละ IP
struct {
    __uint(type, BPF_MAP_TYPE_HASH);    // ใช้ Hash Map เพื่อเก็บค่าจำนวนแพ็กเก็ตต่อ IP
    __uint(max_entries, 1024);          // รองรับสูงสุด 1024 IP
    __type(key, __be32);                // คีย์เป็นค่า IP ต้นทาง (src_ip)
    __type(value, __u32);               // ค่าคือจำนวนแพ็กเก็ตที่ส่งมา
} packet_count_map SEC(".maps");

// ฟังก์ชันสำหรับแปลงค่า Endian ของ IP (จาก Network Byte Order → Host Byte Order)
static __inline __u32 bpf_ntohl(__u32 x) {
    return ((x >> 24) & 0x000000FF) |  // สลับไบต์ที่ 4 → 1
           ((x >>  8) & 0x0000FF00) |  // สลับไบต์ที่ 3 → 2
           ((x <<  8) & 0x00FF0000) |  // สลับไบต์ที่ 2 → 3
           ((x << 24) & 0xFF000000);   // สลับไบต์ที่ 1 → 4
}

// ฟังก์ชันหลักของ XDP สำหรับตรวจสอบและควบคุมแพ็กเก็ต
SEC("xdp")
int xdp_rate_limit(struct xdp_md *ctx) {
    // กำหนดขอบเขตข้อมูลของแพ็กเก็ต
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    
    // อ่านค่าหัวข้อ Ethernet และตรวจสอบขนาดข้อมูล
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) return XDP_DROP; // ถ้าข้อมูล Ethernet header ไม่ครบ ดรอปแพ็กเก็ต
    
    // ตรวจสอบว่าแพ็กเก็ตนี้เป็น IPv4 หรือไม่
    if (eth->h_proto != __constant_htons(ETH_P_IP)) return XDP_PASS; // ถ้าไม่ใช่ IPv4 ให้ปล่อยผ่าน
    
    // อ่านค่าหัวข้อ IP และตรวจสอบขนาดข้อมูล
    struct iphdr *ip = (struct iphdr *)(eth + 1);
    if ((void *)(ip + 1) > data_end) return XDP_DROP; // ถ้าข้อมูล IP header ไม่ครบ ดรอปแพ็กเก็ต
    
    // ดึงค่า IP ต้นทางจาก IP header
    __be32 src_ip = ip->saddr;
    __u32 ip_key = bpf_ntohl(src_ip);  // แปลงค่า IP จาก Network Byte Order เป็น Host Byte Order
    
    // ค้นหาค่าใน BPF map เพื่อดูว่ามีการบันทึกจำนวนแพ็กเก็ตของ IP นี้หรือไม่
    __u32 *count = bpf_map_lookup_elem(&packet_count_map, &ip_key);
    
    if (count) {
        if (*count >= MAX_PACKETS) {
            return XDP_DROP; // ถ้าแพ็กเก็ตจาก IP นี้เกิน 10 ให้ดรอป
        }
        (*count)++; // เพิ่มจำนวนแพ็กเก็ตที่บันทึกไว้
    } else {
        __u32 init_count = 1;
        bpf_map_update_elem(&packet_count_map, &ip_key, &init_count, BPF_ANY); // ถ้ายังไม่มีค่าใน map ให้เริ่มนับจาก 1
    }
    
    return XDP_PASS; // ถ้ายังไม่เกิน 10 ให้ปล่อยแพ็กเก็ตผ่าน
}

// กำหนดลิขสิทธิ์ของโปรแกรมให้เป็น GPL เพื่อให้ eBPF โหลดได้
char _license[] SEC("license") = "GPL";
