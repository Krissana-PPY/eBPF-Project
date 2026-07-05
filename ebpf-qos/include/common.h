/* include/common.h
 * Phase 4: ECN Marking + Shared Pool + EF Passthrough + EDT
 */

#ifndef __COMMON_H__
#define __COMMON_H__

#define TC_EF    0
#define TC_AF    1
#define TC_BE    2
#define TC_MAX   3

#define DSCP_EF     46
#define DSCP_AF41   34
#define DSCP_AF31   26
#define DSCP_AF21   18
#define DSCP_BE      0

#define TOS_TO_DSCP(tos)  ((tos) >> 2)
#define NSEC_PER_SEC       1000000000ULL

/* ECN bits in TOS byte (lowest 2 bits) */
#define ECN_MASK        0x03
#define ECN_NOT_ECT     0x00   /* Not ECN-Capable */
#define ECN_ECT1        0x01   /* ECN Capable (1) */
#define ECN_ECT0        0x02   /* ECN Capable (0) */
#define ECN_CE          0x03   /* Congestion Experienced */

/* Per-class config */
struct class_config {
    __u64 rate_bps;      /* Guaranteed rate (bytes/sec)   */
    __u64 ceil_bps;      /* Max rate with borrowing       */
};

/* Per-class pacing state */
struct class_state {
    __u64 t_rate;        /* Next eligible time at rate    */
    __u64 t_ceil;        /* Next eligible time at ceil    */
};

/* Shared pool — tracks total bandwidth usage */
struct pool_state {
    __u64 total_bytes;   /* Bytes sent in current window  */
    __u64 window_start;  /* Window start timestamp        */
};

/* Per-class statistics */
struct class_stats {
    __u64 packets;       /* Total packets sent            */
    __u64 bytes;         /* Total bytes sent              */
    __u64 borrowed;      /* Sent using borrowed BW        */
    __u64 ecn_marked;    /* Packets marked with ECN CE    */
    __u64 delayed;       /* Packets delayed via EDT       */
};

/* Pool config */
#define POOL_KEY           0
#define POOL_WINDOW_NS     (100 * 1000000ULL)  /* 100ms window */
#define LINK_CAPACITY_BPS  (1000ULL * 1000000 / 8)  /* 1 Gbps in bytes/s */

#endif /* __COMMON_H__ */
