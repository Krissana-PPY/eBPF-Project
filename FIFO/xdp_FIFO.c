// SPDX-License-Identifier: GPL-2.0
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/if_ether.h>
#include <linux/ip.h>

// โครงสร้าง meta data สำหรับแต่ละ packet (ไม่ต้องใช้ flow id)
struct pkt_fifo_meta {
    __u64 pkt_len;
    __u64 timestamp;
    __u64 sequence;
};

// global sequence number (shared counter)
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u64));
    __uint(max_entries, 1);
} global_seq SEC(".maps");

// perf event map สำหรับส่งข้อมูลไป userspace
struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(int));
    __uint(value_size, sizeof(__u32));
    __uint(max_entries, 64);
} events SEC(".maps");

SEC("xdp")
int xdp_fifo_sched(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    // ตรวจสอบและอ่าน Ethernet header เฉยๆ จะเป็นแพ็กเก็ตประเภทใดก็ได้
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_ABORTED;

    // ดึง time และ length
    __u64 timestamp = bpf_ktime_get_ns();
    __u64 pkt_len = data_end - data;

    // การนับ sequence (counter เดียวสำหรับทุก packet)
    __u32 key = 0;
    __u64 *seq_p = bpf_map_lookup_elem(&global_seq, &key);
    __u64 seq = 0;
    if (seq_p) {
        seq = __sync_fetch_and_add(seq_p, 1);
    } else {
        __u64 start = 1;
        bpf_map_update_elem(&global_seq, &key, &start, BPF_NOEXIST);
        seq = 0;
    }

    // เตรียม meta และส่งไป userspace
    struct pkt_fifo_meta meta = {};
    meta.pkt_len = pkt_len;
    meta.timestamp = timestamp;
    meta.sequence = seq;

    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &meta, sizeof(meta));

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";