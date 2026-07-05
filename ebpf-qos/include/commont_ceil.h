/* include/common.h
 * Phase 3: EDT Shaping with Time-based Pacing + Borrowing
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

/* Per-class config: rate (guaranteed) + ceil (max with borrowing) */
struct class_config {
    __u64 rate_bps;      /* Guaranteed rate (bytes/sec)              */
    __u64 ceil_bps;      /* Maximum rate with borrowing (bytes/sec)  */
};

/* Per-class pacing state */
struct class_state {
    __u64 t_rate;        /* Next eligible time at guaranteed rate    */
    __u64 t_ceil;        /* Next eligible time at ceil rate          */
};

/* Per-class statistics */
struct class_stats {
    __u64 packets;       /* Packets sent within guaranteed rate      */
    __u64 bytes;
    __u64 borrowed;      /* Packets sent using borrowed bandwidth    */
    __u64 delayed;       /* Packets delayed by FQ (over ceil)        */
};

#endif /* __COMMON_H__ */
