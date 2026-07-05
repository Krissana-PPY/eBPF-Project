/* src/loader.c
 * Userspace program to:
 *   1. Attach eBPF classifier+ratelimiter to TC egress
 *   2. Configure per-class rate limits via config_map
 *   3. Display real-time stats with pass/drop counters
 *
 * Usage: sudo ./loader <interface> [ef_mbps af_mbps be_mbps]
 * Example: sudo ./loader ens19 500 300 200
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <net/if.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include "common.h"

static volatile int running = 1;
void sig_handler(int sig) { running = 0; }

static const char *class_names[TC_MAX] = {
    [TC_EF] = "EF  (VoIP)  ",
    [TC_AF] = "AF  (Video) ",
    [TC_BE] = "BE  (Default)",
};

static int tc_attach(const char *ifname, const char *obj_path)
{
    char cmd[512];
    snprintf(cmd, sizeof(cmd), "tc qdisc del dev %s clsact 2>/dev/null", ifname);
    (void)system(cmd);
    snprintf(cmd, sizeof(cmd), "tc qdisc add dev %s clsact", ifname);
    if (system(cmd) != 0) { fprintf(stderr, "ERROR: clsact failed\n"); return -1; }
    snprintf(cmd, sizeof(cmd), "tc filter add dev %s ingress bpf da obj %s sec tc", ifname, obj_path);
    if (system(cmd) != 0) { fprintf(stderr, "ERROR: attach failed\n"); return -1; }
    printf("  ✓ eBPF attached to %s (ingress)\n", ifname);
    return 0;
}

static void tc_detach(const char *ifname)
{
    char cmd[256];
    snprintf(cmd, sizeof(cmd), "tc qdisc del dev %s clsact 2>/dev/null", ifname);
    (void)system(cmd);
    printf("\n  ✓ Detached from %s\n", ifname);
}

/* Find map fd by name from kernel */
static int find_map_fd(const char *name, int type, int max_entries)
{
    __u32 id = 0;
    while (bpf_map_get_next_id(id, &id) == 0) {
        int fd = bpf_map_get_fd_by_id(id);
        if (fd < 0) continue;
        struct bpf_map_info info = {};
        __u32 len = sizeof(info);
        if (bpf_map_get_info_by_fd(fd, &info, &len) == 0 &&
            strcmp(info.name, name) == 0 &&
            info.type == type &&
            info.max_entries == max_entries)
            return fd;
        close(fd);
    }
    return -1;
}

/* Set rate config for a class */
static int set_rate(int config_fd, __u32 class_id, __u64 rate_mbps)
{
    struct bucket_config cfg = {
        .rate_bps = rate_mbps * 1000000 / 8,  /* Mbps → bytes/sec */
        .burst = DEFAULT_BURST,
    };
    return bpf_map_update_elem(config_fd, &class_id, &cfg, BPF_ANY);
}

static void print_stats(int stats_fd, __u64 rates[TC_MAX])
{
    struct class_stats s[TC_MAX] = {};
    static struct class_stats prev[TC_MAX] = {};

    for (__u32 i = 0; i < TC_MAX; i++)
        bpf_map_lookup_elem(stats_fd, &i, &s[i]);

    printf("\033[2J\033[H");
    printf("╔═══════════════════════════════════════════════════════════════════════════════╗\n");
    printf("║          eBPF QoS — Classifier + Rate Limiter (Token Bucket)                 ║\n");
    printf("╠═══════════════════════════════════════════════════════════════════════════════╣\n");
    printf("║  Class          │  Rate Limit │  Passed      │  Dropped     │  Mbit/s  │ D%%  ║\n");
    printf("╠═════════════════╪═════════════╪══════════════╪══════════════╪══════════╪═════╣\n");

    __u64 tp = 0, td = 0;
    for (int i = 0; i < TC_MAX; i++) {
        __u64 bps = (s[i].bytes - prev[i].bytes) * 8;
        double mbps = (double)bps / 1000000.0;
        __u64 total = s[i].packets + s[i].dropped;
        double drop_pct = total > 0 ? (double)s[i].dropped / (double)total * 100.0 : 0;
        tp += s[i].packets; td += s[i].dropped;

        printf("║  %s │  %4llu Mbps  │  %10llu  │  %10llu  │  %6.1f  │ %3.0f%% ║\n",
            class_names[i], rates[i], s[i].packets, s[i].dropped, mbps, drop_pct);
    }

    printf("╠═════════════════╪═════════════╪══════════════╪══════════════╪══════════╪═════╣\n");
    double total_dp = (tp+td) > 0 ? (double)td/(double)(tp+td)*100.0 : 0;
    printf("║  TOTAL           │             │  %10llu  │  %10llu  │          │ %3.0f%% ║\n",
        tp, td, total_dp);
    printf("╚═══════════════════════════════════════════════════════════════════════════════╝\n");
    printf("\n  Rate Policy: EF=%llu AF=%llu BE=%llu Mbps (Total=%llu Mbps)\n",
        rates[TC_EF], rates[TC_AF], rates[TC_BE],
        rates[TC_EF] + rates[TC_AF] + rates[TC_BE]);
    printf("  Press Ctrl+C to stop\n");

    memcpy(prev, s, sizeof(prev));
}

int main(int argc, char **argv)
{
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <interface> [ef_mbps af_mbps be_mbps]\n", argv[0]);
        fprintf(stderr, "Example: %s ens19 500 300 200\n", argv[0]);
        return 1;
    }

    const char *ifname = argv[1];
    const char *obj_path = "src/classifier.bpf.o";

    /* Parse rate limits (default: 500/300/200 Mbps) */
    __u64 rates[TC_MAX];
    rates[TC_EF] = argc > 2 ? atoi(argv[2]) : 500;
    rates[TC_AF] = argc > 3 ? atoi(argv[3]) : 300;
    rates[TC_BE] = argc > 4 ? atoi(argv[4]) : 200;

    if (if_nametoindex(ifname) == 0) {
        fprintf(stderr, "ERROR: Interface '%s' not found\n", ifname);
        return 1;
    }

    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    printf("\n  ╔══════════════════════════════════════╗\n");
    printf("  ║  eBPF QoS — Phase 2: Rate Limiter   ║\n");
    printf("  ╠══════════════════════════════════════╣\n");
    printf("  ║  Interface: %-24s ║\n", ifname);
    printf("  ║  EF Rate:   %-4llu Mbps               ║\n", rates[TC_EF]);
    printf("  ║  AF Rate:   %-4llu Mbps               ║\n", rates[TC_AF]);
    printf("  ║  BE Rate:   %-4llu Mbps               ║\n", rates[TC_BE]);
    printf("  ╚══════════════════════════════════════╝\n\n");

    /* Attach eBPF */
    if (tc_attach(ifname, obj_path) != 0)
        return 1;

    sleep(1);

    /* Find maps */
    int stats_fd = find_map_fd("stats_map", BPF_MAP_TYPE_ARRAY, TC_MAX);
    int config_fd = find_map_fd("config_map", BPF_MAP_TYPE_ARRAY, TC_MAX);

    if (stats_fd < 0 || config_fd < 0) {
        fprintf(stderr, "ERROR: Cannot find maps (stats=%d config=%d)\n", stats_fd, config_fd);
        tc_detach(ifname);
        return 1;
    }
    printf("  ✓ Maps found (stats_fd=%d, config_fd=%d)\n", stats_fd, config_fd);

    /* Set rate configs */
    set_rate(config_fd, TC_EF, rates[TC_EF]);
    set_rate(config_fd, TC_AF, rates[TC_AF]);
    set_rate(config_fd, TC_BE, rates[TC_BE]);
    printf("  ✓ Rate limits configured\n");
    printf("  Monitoring... (Ctrl+C to stop)\n\n");
    sleep(1);

    /* Stats loop */
    while (running) {
        print_stats(stats_fd, rates);
        sleep(1);
    }

    close(stats_fd);
    close(config_fd);
    tc_detach(ifname);
    return 0;
}
