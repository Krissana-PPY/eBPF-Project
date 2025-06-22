#include "red_map.h" // include header สำหรับ map
#include <linux/bpf.h> // include header สำหรับ bpf
#include <bpf/bpf_helpers.h> // include helper functions ของ bpf
#include <linux/skbuff.h> // include header สำหรับ sk_buff
#include <linux/netdevice.h> // include header สำหรับ network device
#include <linux/pkt_sched.h> // include header สำหรับ packet scheduler

SEC("kprobe/sch_direct_xmit") // ระบุ section สำหรับ kprobe ที่ function sch_direct_xmit
int kprobe__sch_direct_xmit(struct pt_regs *ctx) {
    struct Qdisc *q = (struct Qdisc *)PT_REGS_PARM2(ctx); // ดึง pointer ของ Qdisc จาก parameter ที่ 2
    __u32 key = 0; // กำหนด key สำหรับ map
    __u32 level; // ตัวแปรเก็บระดับ RED

    if (!q) // ถ้า q เป็น null
        return 0; // ออกจาก function

    __u32 qlen = BPF_CORE_READ(q, q.qlen); // อ่านค่า qlen (queue length) จาก Qdisc

    __u32 *max_ptr = bpf_map_lookup_elem(&max_qlen_map, &key); // อ่านค่า max_qlen จาก map
    if (!max_ptr || *max_ptr == 0) // ถ้าอ่านไม่ได้หรือค่าเป็น 0
        return 0; // ออกจาก function

    __u32 max_qlen = *max_ptr; // กำหนดค่า max_qlen

    // คำนวณระดับปัจจุบันของ queue
    double percent = ((double)qlen / (double)max_qlen) * 100.0;
    if (percent <= 19.0) { // 0%-19% เป็นโซนเขียว
        level = 0;
    } else if (percent <= 60.0) { // 20%-60% เป็นโซนเหลือง
        level = 1;
    } else { // 61%-100% เป็นโซนแดง
        level = 2;
    }

    // อ่านค่าเดิมจาก map
    __u32 *current_level = bpf_map_lookup_elem(&red_state_map, &key); // อ่านค่าระดับ RED ปัจจุบันจาก map
    if (!current_level || *current_level != level) { // ถ้ายังไม่มีหรือค่าต่างจากที่คำนวณได้
        // เขียนเฉพาะเมื่อ level เปลี่ยน
        bpf_map_update_elem(&red_state_map, &key, &level, BPF_ANY); // อัพเดทค่า level ลง map
    }

    return 0; // จบการทำงาน
}

