/* src/classifier.bpf.c
 * eBPF Traffic Classifier + Per-Class Token Bucket Rate Limiter
 *
 * Phase 1: Reads DSCP → assigns traffic class
 * Phase 2: Token Bucket rate limiting per class
 *
 * Packets exceeding the rate are DROPPED (TC_ACT_SHOT)
 * Packets within the rate are PASSED  (TC_ACT_OK)
 *
 * Part of: "Improving Network QoS by using eBPF Packet Scheduling"
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

/* Per-class statistics */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, TC_MAX);
    __type(key, __u32);
    __type(value, struct class_stats);
} stats_map SEC(".maps");

/* Per-class token bucket state */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, TC_MAX);
    __type(key, __u32);
    __type(value, struct bucket_state);
} bucket_map SEC(".maps");

/* Per-class token bucket configuration (set by userspace) */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, TC_MAX);
    __type(key, __u32);
    __type(value, struct bucket_config);
} config_map SEC(".maps");

/* ===== Helper: Classify packet by DSCP ===== */

static __always_inline int classify_dscp(__u8 tos)
{
    __u8 dscp = TOS_TO_DSCP(tos);

    switch (dscp) {
    case DSCP_EF:
        return TC_EF;
    case DSCP_AF41:
    case DSCP_AF31:
    case DSCP_AF21:
        return TC_AF;
    default:
        return TC_BE;
    }
}

/* ===== Helper: Token Bucket Rate Limiter ===== */
/*
 * Returns 1 if packet is ALLOWED (tokens available)
 * Returns 0 if packet should be DROPPED (no tokens)
 *
 * Algorithm:
 *   1. Calculate time elapsed since last refill
 *   2. Add tokens based on elapsed time × rate
 *   3. Cap tokens at burst size
 *   4. If tokens >= packet_size → consume tokens, allow
 *   5. If tokens < packet_size → drop
 */

static __always_inline int token_bucket_allow(__u32 class_id, __u32 pkt_len)
{
    struct bucket_config *cfg;
    struct bucket_state *state;
    __u64 now, elapsed, new_tokens;

    cfg = bpf_map_lookup_elem(&config_map, &class_id);
    if (!cfg || cfg->rate_bps == 0)
        return 1;  /* No config → pass through (no rate limit) */

    state = bpf_map_lookup_elem(&bucket_map, &class_id);
    if (!state)
        return 1;

    now = bpf_ktime_get_ns();

    /* First packet — initialize bucket */
    if (state->last_refill == 0) {
        state->tokens = cfg->burst;
        state->last_refill = now;
    }

    /* Calculate elapsed time and add tokens */
    elapsed = now - state->last_refill;

    /*
     * new_tokens = elapsed_ns × rate_bytes_per_sec / 1,000,000,000
     *
     * Split to avoid overflow AND precision loss:
     *   Step 1: elapsed_us = elapsed_ns / 1000          (ns → μs)
     *   Step 2: new_tokens = elapsed_us × rate_bps / 1,000,000  (μs × B/s → bytes)
     *
     * Example: elapsed=1000ns (1μs), rate=62500000 B/s (500Mbps)
     *   elapsed_us = 1
     *   new_tokens = 1 × 62500000 / 1000000 = 62 bytes per μs
     *   = 62.5 MB/s = 500 Mbps ✓
     *
     * Max safe elapsed before overflow: 18.4×10¹⁸ / 62500000 = 294 billion μs
     *   = ~3.4 days, so no overflow concern
     */
    if (elapsed > 0) {
        __u64 elapsed_us = elapsed / 1000;
        if (elapsed_us > 0) {
            new_tokens = elapsed_us * cfg->rate_bps / 1000000;

            state->tokens += new_tokens;

            /* Cap at burst size */
            if (state->tokens > cfg->burst)
                state->tokens = cfg->burst;

            state->last_refill = now;
        }
    }

    /* Check if enough tokens for this packet */
    if (state->tokens >= pkt_len) {
        state->tokens -= pkt_len;
        return 1;  /* ALLOW */
    }

    return 0;  /* DROP */
}

/* ===== Main TC Program ===== */

SEC("tc")
int classify_and_ratelimit(struct __sk_buff *skb)
{
    void *data     = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;

    /* Parse Ethernet */
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return TC_ACT_OK;

    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return TC_ACT_OK;

    /* Parse IP */
    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return TC_ACT_OK;

    /* Classify by DSCP */
    int tc_class = classify_dscp(ip->tos);
    skb->priority = tc_class;

    /* Rate limit check */
    __u32 key = tc_class;
    int allowed = token_bucket_allow(key, skb->len);

    struct class_stats *stats = bpf_map_lookup_elem(&stats_map, &key);
    if (stats) {
        if (allowed) {
            __sync_fetch_and_add(&stats->packets, 1);
            __sync_fetch_and_add(&stats->bytes, skb->len);
        } else {
            __sync_fetch_and_add(&stats->dropped, 1);
        }
    }

    return allowed ? TC_ACT_OK : TC_ACT_SHOT;
}

char _license[] SEC("license") = "GPL";
