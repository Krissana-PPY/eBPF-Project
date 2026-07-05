/* src/classifier.bpf.c
 * Phase 3: Time-based EDT Pacing + Bandwidth Borrowing
 *
 * Instead of token bucket (which has refill race conditions),
 * this version tracks "next eligible send time" per class.
 *
 * Each packet advances the next send time by:
 *   spacing = packet_size × 1,000,000,000 / rate_bytes_per_sec
 *
 * This guarantees packets are evenly spaced at exactly the configured rate.
 *
 * Borrowing: when a class exceeds its guaranteed rate (t_rate)
 * but is still within ceil (t_ceil), it sends using borrowed bandwidth.
 * When over ceil, the packet is delayed via EDT timestamp.
 */

#include <linux/bpf.h>
#include <linux/pkt_cls.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "common.h"

/* ===== Maps ===== */

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, TC_MAX);
    __type(key, __u32);
    __type(value, struct class_stats);
} stats_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, TC_MAX);
    __type(key, __u32);
    __type(value, struct class_state);
} state_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, TC_MAX);
    __type(key, __u32);
    __type(value, struct class_config);
} config_map SEC(".maps");

/* ===== Classifier ===== */

static __always_inline int classify_dscp(__u8 tos)
{
    __u8 dscp = TOS_TO_DSCP(tos);
    switch (dscp) {
    case DSCP_EF:  return TC_EF;
    case DSCP_AF41:
    case DSCP_AF31:
    case DSCP_AF21: return TC_AF;
    default:        return TC_BE;
    }
}

/* ===== Time-based Pacing ===== */
/*
 * For each class, track two timestamps:
 *   t_rate = next time a byte can be sent at GUARANTEED rate
 *   t_ceil = next time a byte can be sent at CEIL rate (borrowing)
 *
 * Spacing between packets:
 *   rate_spacing = pkt_len × 10^9 / rate_bps (nanoseconds)
 *   ceil_spacing = pkt_len × 10^9 / ceil_bps (nanoseconds)
 *
 * Example for BE (200 Mbps rate, 300 Mbps ceil), 1448-byte packet:
 *   rate_spacing = 1448 × 10^9 / 25,000,000 = 57,920 ns (57.9 μs)
 *   ceil_spacing = 1448 × 10^9 / 37,500,000 = 38,613 ns (38.6 μs)
 *
 * Decision:
 *   now >= t_rate → within guaranteed rate → send now
 *   now >= t_ceil → borrowing → send now (using other classes' unused BW)
 *   now <  t_ceil → over ceil → delay to t_ceil (FQ holds the packet)
 */

static __always_inline void pace_packet(struct __sk_buff *skb,
                                         __u32 class_id, __u32 pkt_len)
{
    struct class_config *cfg = bpf_map_lookup_elem(&config_map, &class_id);
    struct class_state  *st  = bpf_map_lookup_elem(&state_map, &class_id);
    struct class_stats  *s   = bpf_map_lookup_elem(&stats_map, &class_id);

    if (!cfg || !st || !s || cfg->rate_bps == 0)
        return;

    __u64 now = bpf_ktime_get_ns();

    /* Calculate spacing for this packet */
    __u64 rate_spacing = (__u64)pkt_len * NSEC_PER_SEC / cfg->rate_bps;
    __u64 ceil_spacing = (__u64)pkt_len * NSEC_PER_SEC / cfg->ceil_bps;

    /* Reset stale timestamps (if no traffic for >1 second, reset) */
    if (st->t_rate != 0 && now > st->t_rate + NSEC_PER_SEC)
        st->t_rate = 0;
    if (st->t_ceil != 0 && now > st->t_ceil + NSEC_PER_SEC)
        st->t_ceil = 0;

    if (now >= st->t_rate) {
        /*
         * Case 1: Within guaranteed rate — send immediately
         * Advance both rate and ceil timestamps
         */
        st->t_rate = now + rate_spacing;
        st->t_ceil = now + ceil_spacing;

        bpf_skb_set_tstamp(skb, 0, BPF_SKB_TSTAMP_UNSPEC);

        __sync_fetch_and_add(&s->packets, 1);
        __sync_fetch_and_add(&s->bytes, pkt_len);

    } else if (now >= st->t_ceil) {
        /*
         * Case 2: Borrowing — over rate, within ceil
         * Send now but advance ceil timestamp
         * (rate timestamp stays ahead — class is "in debt")
         */
        st->t_ceil = now + ceil_spacing;

        bpf_skb_set_tstamp(skb, 0, BPF_SKB_TSTAMP_UNSPEC);

        __sync_fetch_and_add(&s->packets, 1);
        __sync_fetch_and_add(&s->bytes, pkt_len);
        __sync_fetch_and_add(&s->borrowed, 1);

    } else {
        /*
         * Case 3: Over ceil — DELAY packet
         * Set EDT = t_ceil (when this packet is allowed to depart)
         * FQ qdisc will hold the packet until that time
         * Advance t_ceil for the next packet
         */
        __u64 edt = st->t_ceil;

        /* Safety: don't delay more than 100ms */
        if (edt > now + 100000000ULL)
            edt = now + 100000000ULL;

        bpf_skb_set_tstamp(skb, edt, BPF_SKB_TSTAMP_DELIVERY_MONO);

        st->t_ceil = edt + ceil_spacing;

        __sync_fetch_and_add(&s->packets, 1);
        __sync_fetch_and_add(&s->bytes, pkt_len);
        __sync_fetch_and_add(&s->delayed, 1);
    }
}

/* ===== Main ===== */

SEC("tc")
int classify_and_shape(struct __sk_buff *skb)
{
    void *data     = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return TC_ACT_OK;

    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return TC_ACT_OK;

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return TC_ACT_OK;

    int tc_class = classify_dscp(ip->tos);
    skb->priority = tc_class;

    pace_packet(skb, tc_class, skb->len);

    return TC_ACT_OK;
}

char _license[] SEC("license") = "GPL";
