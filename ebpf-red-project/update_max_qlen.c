#include <bpf/libbpf.h> // include libbpf สำหรับใช้งาน bpf
#include <stdio.h> // include สำหรับ printf
#include <stdlib.h> // include สำหรับ strtoul

int main(int argc, char **argv) {
    if (argc != 2) { // ตรวจสอบว่ามี argument 2 ตัวหรือไม่
        printf("Usage: %s <max_qlen>\n", argv[0]); // แสดงวิธีใช้งาน
        return 1; // ออกจากโปรแกรม
    }

    __u32 max_qlen = (unsigned int)strtoul(argv[1], NULL, 10); // แปลง argument เป็นตัวเลข
    __u32 key = 0; // กำหนด key สำหรับ map

    int map_fd = bpf_obj_get("/sys/fs/bpf/max_qlen_map"); // เปิด map ที่ path นี้
    if (map_fd < 0) { // ถ้าเปิดไม่ได้
        perror("bpf_obj_get max_qlen_map"); // แสดง error
        return 1; // ออกจากโปรแกรม
    }

    if (bpf_map_update_elem(map_fd, &key, &max_qlen, BPF_ANY) < 0) { // อัพเดทค่า max_qlen ลง map
        perror("bpf_map_update_elem"); // แสดง error
        return 1; // ออกจากโปรแกรม
    }

    printf("Updated max_qlen to %u\n", max_qlen); // แสดงผลลัพธ์
    return 0; // จบโปรแกรม
}
