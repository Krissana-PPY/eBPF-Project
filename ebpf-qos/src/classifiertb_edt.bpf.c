/* src/classifier.bpf.c
 * Phase 3: EDT-based Traffic Shaping + Bandwidth Borrowing
 *
 * Instead of DROPPING packets (policing), this version DELAYS them
 * by setting EDT (Earliest Departure Time) on skb->tstamp.
 * FQ qdisc then holds packets until their departure time.
 *
 * Each class has:
 *   rate = guaranteed bandwidth (always available)
 *   ceil = maximum bandwidth (including borrowed from other classes)
 *
 * Borrowing: when a class exceeds its rate but stays under ceil,
 * it "borrows" bandwidth that other classes aren't using.
 * FQ qdisc handles this naturally — if EF has no traffic,
 * AF/BE packets depart sooner because the link is free.
 *
 * Key difference from Phase 2:
 *   Phase 2: over limit → TC_ACT_SHOT (drop)
 *   Phase 3: over limit → set skb->tstamp (delay) → TC_ACT_OK (pass)
 */

#include <linux/bpf.h>
#include <linux/pkt_cls.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "common.h"

/* ===== eBPF Maps ===== */

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

/* ===== DSCP Classifier (same as before) ===== */

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

/* ===== EDT Shaping + Borrowing ===== */
/*
 * Instead of drop, calculate when this packet should depart.
 *
 * Two token buckets per class:
 *   rate_tokens: refills at rate_bps (guaranteed bandwidth)
 *   ceil_tokens: refills at ceil_bps (max bandwidth with borrowing)
 *
 * Decision:
 *   rate_tokens >= pkt_len  → within guaranteed rate → send now
 *   rate_tokens < pkt_len, ceil_tokens >= pkt_len → borrowing → send now
 *   ceil_tokens < pkt_len  → over ceil → delay packet
 *
 * NEVER DROP. Always TC_ACT_OK.
 */

static __always_inline void shape_packet(struct __sk_buff *skb,
                                          __u32 class_id, __u32 pkt_len)
{
    struct class_config *cfg = bpf_map_lookup_elem(&config_map, &class_id);
    struct class_state *st   = bpf_map_lookup_elem(&state_map, &class_id);
    struct class_stats *stat = bpf_map_lookup_elem(&stats_map, &class_id);

    if (!cfg || !st || !stat)
        return;

    /* No config → no shaping */
    if (cfg->rate_bps == 0)
        return;

    __u64 now = bpf_ktime_get_ns();

    /* Initialize on first packet */
    if (st->last_update == 0) {
        st->tokens = cfg->burst;
        st->ceil_tokens = cfg->burst;
        st->last_update = now;
    }

    /* Refill tokens based on elapsed time */
    __u64 elapsed = now - st->last_update;
    if (elapsed > 0) {
        /* Rate tokens: refill at guaranteed rate */
        __u64 rate_refill = elapsed * cfg->rate_bps / NSEC_PER_SEC;
        st->tokens += rate_refill;
        if (st->tokens > cfg->burst)
            st->tokens = cfg->burst;

        /* Ceil tokens: refill at max rate (for borrowing) */
        __u64 ceil_refill = elapsed * cfg->ceil_bps / NSEC_PER_SEC;
        st->ceil_tokens += ceil_refill;
        if (st->ceil_tokens > cfg->burst)
            st->ceil_tokens = cfg->burst;

        st->last_update = now;
    }

    /* ===== Decision ===== */

    if (st->tokens >= pkt_len) {
        /*
         * Case 1: Within guaranteed rate — send immediately
         */
        st->tokens -= pkt_len;
        st->ceil_tokens -= pkt_len;

        /* Clear any previous timestamp — send ASAP */
        bpf_skb_set_tstamp(skb, 0, BPF_SKB_TSTAMP_UNSPEC);

        __sync_fetch_and_add(&stat->packets, 1);
        __sync_fetch_and_add(&stat->bytes, pkt_len);

    } else if (st->ceil_tokens >= pkt_len) {
        /*
         * Case 2: Borrowing — over rate but within ceil
         */
        st->ceil_tokens -= pkt_len;
        if (st->tokens >= pkt_len)
            st->tokens -= pkt_len;
        else
            st->tokens = 0;

        /* Borrowing — still send now */
        bpf_skb_set_tstamp(skb, 0, BPF_SKB_TSTAMP_UNSPEC);

        __sync_fetch_and_add(&stat->packets, 1);
        __sync_fetch_and_add(&stat->bytes, pkt_len);
        __sync_fetch_and_add(&stat->borrowed, 1);

    } else {
        /*
         * Case 3: Over ceil — must delay
         * Set EDT as DELIVERY_MONO so FQ qdisc knows to hold it
         */
        __u64 deficit = pkt_len - st->ceil_tokens;
        __u64 delay_ns = deficit * NSEC_PER_SEC / cfg->ceil_bps;

        if (delay_ns > 100000000ULL)
            delay_ns = 100000000ULL;

        /* KEY: use bpf_skb_set_tstamp with DELIVERY_MONO
         * This tells FQ qdisc this is a departure time, not a receive time */
        bpf_skb_set_tstamp(skb, now + delay_ns, BPF_SKB_TSTAMP_DELIVERY_MONO);

        st->ceil_tokens = 0;
        st->tokens = 0;

        __sync_fetch_and_add(&stat->packets, 1);
        __sync_fetch_and_add(&stat->bytes, pkt_len);
        __sync_fetch_and_add(&stat->delayed, 1);
    }
}

/* ===== Main TC Program ===== */

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

    /* Classify */
    int tc_class = classify_dscp(ip->tos);
    skb->priority = tc_class;

    /* Shape (delay instead of drop) */
    shape_packet(skb, tc_class, skb->len);

    /* ALWAYS pass — never drop */
    return TC_ACT_OK;
}

char _license[] SEC("license") = "GPL";
