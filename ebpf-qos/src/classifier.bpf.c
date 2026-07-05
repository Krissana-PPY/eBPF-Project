/* src/classifier.bpf.c
 * Phase 4: ECN Marking + Shared Pool + EF Passthrough + EDT
 *
 * 4 improvements over Phase 3:
 *   1. EF passthrough — highest priority, never paced/marked
 *   2. ECN marking — tell TCP to slow down without drop/delay
 *   3. Shared pool — track total usage, enable smart borrowing
 *   4. EDT fallback — for non-ECN traffic (UDP) or over-ceil
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

/* Shared pool — single entry, tracks total bandwidth */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct pool_state);
} pool_map SEC(".maps");

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

/* ===== ECN Marking ===== */
/*
 * Mark ECN CE (Congestion Experienced) on a packet.
 * TCP receiver will echo this back → TCP sender reduces rate.
 * No packet loss → no retransmit!
 *
 * Returns: 1 if marked, 0 if not ECN-capable
 */

static __always_inline int mark_ecn_ce(struct __sk_buff *skb,
                                        struct iphdr *ip)
{
    __u8 ecn = ip->tos & ECN_MASK;

    /* Only mark if ECN-capable (ECT(0) or ECT(1)) */
    if (ecn != ECN_ECT0 && ecn != ECN_ECT1)
        return 0;  /* Not ECN-capable (e.g. UDP without ECN) */

    __u8 old_tos = ip->tos;
    __u8 new_tos = (old_tos & ~ECN_MASK) | ECN_CE;

    if (old_tos == new_tos)
        return 1;  /* Already CE */

    /* Update IP checksum for TOS change */
    bpf_l3_csum_replace(skb,
        ETH_HLEN + offsetof(struct iphdr, check),
        (__u32)old_tos, (__u32)new_tos, 2);

    /* Write new TOS byte */
    bpf_skb_store_bytes(skb,
        ETH_HLEN + offsetof(struct iphdr, tos),
        &new_tos, sizeof(new_tos), 0);

    return 1;
}

/* ===== Shared Pool ===== */
/*
 * Track total bytes sent across all classes.
 * If total < link_capacity → spare bandwidth exists → borrowing OK
 */

static __always_inline int pool_has_spare(struct __sk_buff *skb,
                                           __u32 pkt_len, __u64 now)
{
    __u32 key = POOL_KEY;
    struct pool_state *pool = bpf_map_lookup_elem(&pool_map, &key);
    if (!pool)
        return 1;  /* No pool → assume spare */

    /* Reset window every 100ms */
    if (pool->window_start == 0 || (now - pool->window_start) > POOL_WINDOW_NS) {
        pool->total_bytes = 0;
        pool->window_start = now;
    }

    /* Check if link still has capacity */
    __u64 window_elapsed = now - pool->window_start;
    __u64 allowed_bytes = window_elapsed * LINK_CAPACITY_BPS / NSEC_PER_SEC;

    /* Update total */
    pool->total_bytes += pkt_len;

    return (pool->total_bytes <= allowed_bytes) ? 1 : 0;
}

/* ===== Main QoS Engine ===== */

static __always_inline void qos_engine(struct __sk_buff *skb,
                                        struct iphdr *ip,
                                        __u32 class_id, __u32 pkt_len)
{
    struct class_config *cfg = bpf_map_lookup_elem(&config_map, &class_id);
    struct class_state  *st  = bpf_map_lookup_elem(&state_map, &class_id);
    struct class_stats  *s   = bpf_map_lookup_elem(&stats_map, &class_id);

    if (!cfg || !st || !s)
        return;

    __u64 now = bpf_ktime_get_ns();

    /* ===== Rule 1: EF = highest priority, ALWAYS pass ===== */
    if (class_id == TC_EF) {
        /* No pacing, no ECN, no delay — EF gets everything first */
        __sync_fetch_and_add(&s->packets, 1);
        __sync_fetch_and_add(&s->bytes, pkt_len);
        pool_has_spare(skb, pkt_len, now);  /* Just track usage */
        return;
    }

    /* No config → pass through */
    if (cfg->rate_bps == 0) {
        __sync_fetch_and_add(&s->packets, 1);
        __sync_fetch_and_add(&s->bytes, pkt_len);
        return;
    }

    /* Calculate pacing intervals */
    __u64 rate_spacing = (__u64)pkt_len * NSEC_PER_SEC / cfg->rate_bps;
    __u64 ceil_spacing = (__u64)pkt_len * NSEC_PER_SEC / cfg->ceil_bps;

    /* Reset stale timestamps */
    if (st->t_rate != 0 && now > st->t_rate + NSEC_PER_SEC)
        st->t_rate = 0;
    if (st->t_ceil != 0 && now > st->t_ceil + NSEC_PER_SEC)
        st->t_ceil = 0;

    int spare = pool_has_spare(skb, pkt_len, now);

    /* ===== Rule 2: Within guaranteed rate → pass ===== */
    if (now >= st->t_rate) {
        st->t_rate = now + rate_spacing;
        st->t_ceil = now + ceil_spacing;

        __sync_fetch_and_add(&s->packets, 1);
        __sync_fetch_and_add(&s->bytes, pkt_len);
        return;
    }

    /* ===== Rule 3: Over rate, within ceil → EDT pacing only ===== */
    /*
     * DON'T mark ECN here — just pace with EDT
     * TCP interprets delay as mild congestion → adjusts rate gradually
     * This is what worked in Phase 3 (AF=429M, BE=272M)
     */
    if (now >= st->t_ceil && spare) {
        st->t_ceil = now + ceil_spacing;

        /* No ECN here — only pacing */
        __sync_fetch_and_add(&s->packets, 1);
        __sync_fetch_and_add(&s->bytes, pkt_len);
        __sync_fetch_and_add(&s->borrowed, 1);
        return;
    }

    /* ===== Rule 4: Over ceil OR no spare → ECN mark + EDT delay ===== */
    /*
     * Now we're really over the limit — use ECN to signal TCP
     * ECN tells sender "you're over ceiling, please reduce"
     * EDT delay gives FQ time to pace the packet
     * 
     * But DON'T mark every packet — mark 1 in 4 to avoid
     * TCP collapsing from continuous CE signals
     */
    {
        __u64 edt = st->t_ceil;
        if (edt < now)
            edt = now;

        if (edt > now + 50000000ULL)
            edt = now + 50000000ULL;

        /* Mark ECN every ~4th packet to avoid over-signaling */
        if ((s->delayed & 3) == 0) {
            if (mark_ecn_ce(skb, ip)) {
                __sync_fetch_and_add(&s->ecn_marked, 1);
            }
        }

        bpf_skb_set_tstamp(skb, edt, BPF_SKB_TSTAMP_DELIVERY_MONO);

        st->t_ceil = edt + ceil_spacing;

        __sync_fetch_and_add(&s->packets, 1);
        __sync_fetch_and_add(&s->bytes, pkt_len);
        __sync_fetch_and_add(&s->delayed, 1);
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

    int tc_class = classify_dscp(ip->tos);
    skb->priority = tc_class;

    qos_engine(skb, ip, tc_class, skb->len);

    return TC_ACT_OK;  /* NEVER drop */
}

char _license[] SEC("license") = "GPL";
