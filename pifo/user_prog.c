#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <net/if.h>            // ใช้สำหรับจัดการกับอินเทอร์เฟซเครือข่าย
#include <bpf/libbpf.h>        // ไลบรารี BPF เพื่อใช้งาน BPF
#include <bpf/bpf.h>           // ไลบรารี BPF สำหรับการคอมไพล์โปรแกรม
#include <linux/if_link.h>     // สำหรับค่าคงที่ XDP
#include <sys/resource.h>      // ใช้สำหรับตั้งค่าทรัพยากรระบบ (เช่นการจัดการหน่วยความจำ)
#include "common.h"            // ไฟล์หัวสำหรับข้อมูลทั่วไป

// ฟังก์ชันนี้จะใช้เพื่อจัดการข้อมูลที่ได้รับจาก perf buffer
static void handle_event(void *ctx, int cpu, void *data, __u32 data_sz) {
    struct pkt_meta *pkt = data;  // การแปลงข้อมูลที่ได้รับใน perf buffer
    printf("flow=%u len=%u prio=%llu\n", pkt->flow_id, pkt->len, pkt->priority);  // แสดงข้อมูล flow_id, length, และ priority ของแพ็กเก็ต
}

int main(int argc, char **argv) {
    struct perf_buffer *pb = NULL;    // ตัวแปรสำหรับเก็บข้อมูล perf buffer
    struct bpf_object *obj = NULL;    // ตัวแปรสำหรับเก็บ object ของ BPF
    struct bpf_program *prog;         // ตัวแปรสำหรับเก็บโปรแกรม BPF
    int prog_fd;                      // ตัวแปรเก็บ descriptor ของโปรแกรม BPF
    int ifindex;                      // ตัวแปรเก็บหมายเลขดัชนีของอินเทอร์เฟซ

    // ตรวจสอบว่ามีการส่งชื่ออินเทอร์เฟซเข้ามาหรือไม่
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <iface>\n", argv[0]);  // ถ้าไม่มีอินเทอร์เฟซส่งมาจะให้ข้อมูลการใช้งาน
        return 1;
    }

    // ตั้งค่าการอนุญาตให้ใช้หน่วยความจำที่ถูกล็อก (ไม่มีการจำกัด)
    struct rlimit r = {RLIM_INFINITY, RLIM_INFINITY};
    setrlimit(RLIMIT_MEMLOCK, &r);  // ทำให้โปรแกรมสามารถใช้หน่วยความจำที่ถูกล็อกได้

    // โหลดไฟล์ BPF object
    obj = bpf_object__open_file("xdp_Q.o", NULL);
    if (!obj) {
        fprintf(stderr, "Error opening BPF object file: %s\n", strerror(errno));  // ถ้าไม่สามารถเปิดไฟล์ได้จะให้ข้อความแสดงข้อผิดพลาด
        return 1;
    }

    // โหลดโปรแกรม BPF จาก object ที่เปิด
    if (bpf_object__load(obj)) {
        fprintf(stderr, "Error loading BPF object: %s\n", strerror(errno));  // ถ้าโหลดโปรแกรม BPF ไม่ได้จะแสดงข้อผิดพลาด
        bpf_object__close(obj);
        return 1;
    }

    // ดึงโปรแกรม BPF ตัวแรกจาก object
    prog = bpf_object__next_program(obj, NULL);
    if (!prog) {
        fprintf(stderr, "No program found in BPF object\n");  // ถ้าไม่มีโปรแกรมใน BPF object
        bpf_object__close(obj);
        return 1;
    }
    prog_fd = bpf_program__fd(prog);  // ดึง descriptor ของโปรแกรม BPF

    // เชื่อมต่อโปรแกรม BPF เข้ากับอินเทอร์เฟซด้วย XDP
    ifindex = if_nametoindex(argv[1]);  // แปลงชื่ออินเทอร์เฟซเป็นหมายเลขดัชนี
    if (ifindex == 0) {
        perror("if_nametoindex");  // ถ้าเกิดข้อผิดพลาดในการแปลงชื่ออินเทอร์เฟซ
        bpf_object__close(obj);
        return 1;
    }
    
    // ใช้ XDP attachment API เพื่อเชื่อมต่อโปรแกรม BPF
    if (bpf_xdp_attach(ifindex, prog_fd, XDP_FLAGS_DRV_MODE, NULL) < 0) {
        perror("bpf_xdp_attach");  // ถ้าไม่สามารถเชื่อมต่อในโหมด driver ได้ ให้แสดงข้อผิดพลาด
        fprintf(stderr, "Fallback to generic/skb mode\n");

        // ถ้าโหมด driver ล้มเหลวให้ลองเชื่อมต่อในโหมด skb
        if (bpf_xdp_attach(ifindex, prog_fd, XDP_FLAGS_SKB_MODE, NULL) < 0) {
            perror("bpf_xdp_attach (SKB mode)");  // ถ้าโหมด skb ล้มเหลว
            bpf_object__close(obj);
            return 1;
        }
    }

    // ตั้งค่า perf buffer
    int map_fd = bpf_map__fd(bpf_object__find_map_by_name(obj, "events"));
    if (map_fd < 0) {
        fprintf(stderr, "Failed to get map fd: %s\n", strerror(errno));  // ถ้าไม่สามารถดึง map fd ได้
        bpf_xdp_detach(ifindex, XDP_FLAGS_MASK, NULL);  // ถอดโปรแกรม XDP ออก
        bpf_object__close(obj);
        return 1;
    }

    struct perf_buffer_opts pb_opts = {};
    pb_opts.sz = sizeof(struct perf_buffer_opts);  // กำหนดขนาดของ options สำหรับ perf buffer
    pb = perf_buffer__new(map_fd, 8, handle_event, NULL, NULL, &pb_opts);  // สร้าง perf buffer ใหม่
    if (!pb) {
        fprintf(stderr, "Failed to open perf buffer: %s\n", strerror(errno));  // ถ้าไม่สามารถเปิด perf buffer ได้
        bpf_xdp_detach(ifindex, XDP_FLAGS_MASK, NULL);  // ถอดโปรแกรม XDP ออก
        bpf_object__close(obj);
        return 1;
    }

    // เริ่มฟังแพ็กเก็ตจากอินเทอร์เฟซ
    printf("Listening for packets on interface %s...\n", argv[1]);
    while (1) {
        int err = perf_buffer__poll(pb, 100);  // ทำการ poll เพื่อดึงข้อมูลจาก perf buffer
        if (err < 0 && err != -EINTR) {  // ถ้าเกิดข้อผิดพลาดในการ poll
            fprintf(stderr, "Error polling perf buffer: %s\n", strerror(-err));
            break;
        }
    }

    // ทำความสะอาด (free) และปิดการเชื่อมต่อ
    perf_buffer__free(pb);  // ปล่อยทรัพยากร perf buffer
    bpf_xdp_detach(ifindex, XDP_FLAGS_MASK, NULL);  // ถอดโปรแกรม XDP ออกจากอินเทอร์เฟซ
    bpf_object__close(obj);  // ปิด BPF object
    return 0;
}