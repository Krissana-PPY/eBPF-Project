/* include/common.h
 * Phase 3: Shaping (EDT) + Bandwidth Borrowing
 */

#ifndef __COMMON_H__
#define __COMMON_H__

/* ===== Traffic Classes (DiffServ) ===== */

#define TC_EF    0    /* Expedited Forwarding  — VoIP            */
#define TC_AF    1    /* Assured Forwarding    — Video           */
#define TC_BE    2    /* Best Effort           — Web             */
#define TC_MAX   3

/* ===== DSCP Values ===== */

#define DSCP_EF     46
#define DSCP_AF41   34
#define DSCP_AF31   26
#define DSCP_AF21   18
#define DSCP_BE      0

#define TOS_TO_DSCP(tos)  ((tos) >> 2)

/* ===== Per-class Configuration ===== */
/* rate = guaranteed bandwidth (always available)         */
/* ceil = maximum bandwidth (including borrowed)          */
/* burst = max tokens (bucket size)                       */

struct class_config {
    __u64 rate_bps;      /* Guaranteed rate (bytes/sec)   */
    __u64 ceil_bps;      /* Maximum rate (bytes/sec)      */
    __u64 burst;         /* Burst size (bytes)            */
};

/* ===== Per-class Shaping State ===== */

struct class_state {
    __u64 tokens;        /* Current tokens (rate bucket)  */
    __u64 ceil_tokens;   /* Current tokens (ceil bucket)  */
    __u64 last_update;   /* Last update timestamp (ns)    */
};

/* ===== Per-class Statistics ===== */

struct class_stats {
    __u64 packets;       /* Packets sent within rate      */
    __u64 bytes;         /* Bytes sent within rate        */
    __u64 borrowed;      /* Packets sent using borrowed BW*/
    __u64 delayed;       /* Packets delayed (shaped)      */
};

/* ===== Defaults ===== */

#define DEFAULT_BURST     (64 * 1024)               /* 64 KB burst  */
#define NSEC_PER_SEC      1000000000ULL

#endif /* __COMMON_H__ */
