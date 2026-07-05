/* include/common.h
 * Shared definitions between eBPF kernel programs and userspace loader
 * 
 * Part of: "Improving Network QoS by using eBPF Packet Scheduling"
 */

#ifndef __COMMON_H__
#define __COMMON_H__

/* ===== Traffic Classes ===== */
/* Based on DiffServ (RFC 2474) DSCP values */

#define TC_EF    0    /* Expedited Forwarding  — VoIP, real-time       */
#define TC_AF    1    /* Assured Forwarding    — Video, streaming      */
#define TC_BE    2    /* Best Effort           — Web, email            */
#define TC_MAX   3    /* Total number of classes                       */

/* ===== DSCP Values ===== */
/* DSCP is the top 6 bits of the TOS byte in IP header               */
/* TOS byte layout: | DSCP (6 bits) | ECN (2 bits) |                  */

#define DSCP_EF     46   /* 101110  → TOS = 0xB8 (184)               */
#define DSCP_AF41   34   /* 100010  → TOS = 0x88 (136)               */
#define DSCP_AF31   26   /* 011010  → TOS = 0x68 (104)               */
#define DSCP_AF21   18   /* 010010  → TOS = 0x48 (72)                */
#define DSCP_BE      0   /* 000000  → TOS = 0x00 (0)                 */

/* Extract DSCP from TOS byte: shift right 2 bits to remove ECN      */
#define TOS_TO_DSCP(tos)  ((tos) >> 2)

/* ===== Token Bucket Parameters ===== */
/* rate = tokens added per nanosecond (bytes/ns)                      */
/* burst = maximum tokens (bucket size in bytes)                      */

struct bucket_config {
    __u64 rate_bps;      /* Rate in bytes per second                  */
    __u64 burst;         /* Burst size in bytes                       */
};

/* Per-class token bucket state                                       */
/* Maintained in eBPF map, updated on every packet                    */

struct bucket_state {
    __u64 tokens;        /* Current available tokens (bytes)          */
    __u64 last_refill;   /* Last refill timestamp (nanoseconds)       */
};

/* ===== Per-class Statistics ===== */

struct class_stats {
    __u64 packets;       /* Total packets passed                      */
    __u64 bytes;         /* Total bytes passed                        */
    __u64 dropped;       /* Packets dropped by rate limiter           */
};

/* ===== Default QoS Policy ===== */
/* Total = 1 Gbps, EF=50%, AF=30%, BE=20%                            */

#define DEFAULT_EF_RATE   (500ULL * 1000000 / 8)   /* 500 Mbps → bytes/s */
#define DEFAULT_AF_RATE   (300ULL * 1000000 / 8)   /* 300 Mbps → bytes/s */
#define DEFAULT_BE_RATE   (200ULL * 1000000 / 8)   /* 200 Mbps → bytes/s */
#define DEFAULT_BURST     (4 * 1024 * 1024)           /* 4 MB burst         */

#endif /* __COMMON_H__ */
