#include <linux/bpf.h>
#include <linux/if_ether.h>  // ใช้สำหรับโครงสร้าง Ethernet header (ethhdr)
#include <linux/ip.h>        // ใช้สำหรับโครงสร้าง IP header (iphdr)
#include <linux/tcp.h>       // ใช้สำหรับโครงสร้าง TCP header (tcphdr)
#include <linux/in.h>        // ใช้สำหรับกำหนดค่าคงที่ของโปรโตคอล เช่น IPPROTO_TCP
#include <bpf/bpf_helpers.h> // ใช้สำหรับ BPF helper functions

// กำหนดโปรแกรม XDP
SEC("xdp")
int xdp_block_tcp(struct xdp_md *ctx) {
    // ดึง pointer ไปยังจุดเริ่มต้นและจุดสิ้นสุดของ packet
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    // อ่าน Ethernet header
    struct ethhdr *eth = data;

    // ตรวจสอบว่า Ethernet header อยู่ภายในขอบเขตของแพ็กเก็ตหรือไม่
    if ((void *)(eth + 1) > data_end) return XDP_DROP;

    // ตรวจสอบว่าแพ็กเก็ตเป็น IPv4 หรือไม่
    if (eth->h_proto != __constant_htons(ETH_P_IP)) return XDP_PASS;

    // อ่าน IP header (อยู่ถัดจาก Ethernet header)
    struct iphdr *ip = (struct iphdr *)(eth + 1);

    // ตรวจสอบว่า IP header อยู่ภายในขอบเขตของแพ็กเก็ตหรือไม่
    if ((void *)(ip + 1) > data_end) return XDP_DROP;

    // ตรวจสอบว่าเป็น TCP หรือไม่
    if (ip->protocol == IPPROTO_TCP) {
        return XDP_DROP;  // ถ้าเป็น TCP ให้ดรอปแพ็กเก็ต
    }

    return XDP_PASS; // ถ้าไม่ใช่ TCP ให้อนุญาตให้แพ็กเก็ตผ่านไปได้
}

// กำหนด license ให้กับ eBPF program
char _license[] SEC("license") = "GPL";
