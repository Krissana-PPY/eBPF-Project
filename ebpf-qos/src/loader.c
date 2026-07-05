/* src/loader.c
 * Phase 3: EDT Shaping + Borrowing
 *
 * Sets up: FQ qdisc (root) + clsact (BPF hook) + eBPF program
 *
 * Usage: sudo ./loader <iface> <direction> [ef_rate ef_ceil af_rate af_ceil be_rate be_ceil]
 * Example: sudo ./loader ens19 egress 500 800 300 500 200 300
 *
 * rate = guaranteed Mbps, ceil = max Mbps (with borrowing)
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <net/if.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include "common.h"

static volatile int running = 1;
void sig_handler(int sig) { running = 0; }

static const char *class_names[TC_MAX] = {
    [TC_EF] = "EF (VoIP)  ",
    [TC_AF] = "AF (Video) ",
    [TC_BE] = "BE (Default)",
};

static int tc_setup(const char *ifname, const char *obj_path, const char *direction)
{
    char cmd[512];

    /* Remove existing qdiscs */
    snprintf(cmd, sizeof(cmd), "tc qdisc del dev %s clsact 2>/dev/null", ifname);
    (void)system(cmd);
    snprintf(cmd, sizeof(cmd), "tc qdisc del dev %s root 2>/dev/null", ifname);
    (void)system(cmd);

    /* Set FQ as root qdisc — this handles EDT timestamps */
    snprintf(cmd, sizeof(cmd), "tc qdisc add dev %s root fq", ifname);
    if (system(cmd) != 0) {
        fprintf(stderr, "ERROR: Failed to set FQ qdisc\n");
        return -1;
    }
    printf("  ✓ FQ qdisc set as root (handles EDT scheduling)\n");

    /* Add clsact for BPF hooks */
    snprintf(cmd, sizeof(cmd), "tc qdisc add dev %s clsact", ifname);
    if (system(cmd) != 0) {
        fprintf(stderr, "ERROR: Failed to add clsact\n");
        return -1;
    }

    /* Attach BPF program */
    snprintf(cmd, sizeof(cmd),
        "tc filter add dev %s %s bpf da obj %s sec tc",
        ifname, direction, obj_path);
    if (system(cmd) != 0) {
        fprintf(stderr, "ERROR: Failed to attach BPF\n");
        return -1;
    }
    printf("  ✓ eBPF attached to %s (%s)\n", ifname, direction);
    return 0;
}

static void tc_cleanup(const char *ifname)
{
    char cmd[256];
    snprintf(cmd, sizeof(cmd), "tc qdisc del dev %s clsact 2>/dev/null", ifname);
    (void)system(cmd);
    /* Restore default qdisc */
    snprintf(cmd, sizeof(cmd), "tc qdisc replace dev %s root fq_codel", ifname);
    (void)system(cmd);
    printf("\n  ✓ Cleaned up, restored fq_codel on %s\n", ifname);
}

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

static int set_class_config(int config_fd, __u32 class_id,
                             __u64 rate_mbps, __u64 ceil_mbps)
{
    struct class_config cfg = {
        .rate_bps = rate_mbps * 1000000 / 8,
        .ceil_bps = ceil_mbps * 1000000 / 8,
    };
    return bpf_map_update_elem(config_fd, &class_id, &cfg, BPF_ANY);
}

static void print_stats(int stats_fd, __u64 rates[], __u64 ceils[])
{
    struct class_stats s[TC_MAX] = {};
    static struct class_stats prev[TC_MAX] = {};

    for (__u32 i = 0; i < TC_MAX; i++)
        bpf_map_lookup_elem(stats_fd, &i, &s[i]);

    printf("\033[2J\033[H");
    printf("╔═══════════════════════════════════════════════════════════════════════════════════════════╗\n");
    printf("║          eBPF QoS — Phase 4: ECN + Shared Pool + EF Passthrough + EDT                    ║\n");
    printf("╠═══════════════════════════════════════════════════════════════════════════════════════════╣\n");
    printf("║  Class         │ Rate/Ceil   │  Packets     │  Borrowed    │  ECN Mark    │  Delayed     ║\n");
    printf("╠════════════════╪═════════════╪══════════════╪══════════════╪══════════════╪══════════════╣\n");

    __u64 tp = 0, tb = 0, te = 0, td = 0;
    for (int i = 0; i < TC_MAX; i++) {
        __u64 bps = (s[i].bytes - prev[i].bytes) * 8;
        double mbps = (double)bps / 1000000.0;
        tp += s[i].packets;
        tb += s[i].borrowed;
        te += s[i].ecn_marked;
        td += s[i].delayed;

        const char *mode = (i == TC_EF) ? " [PASS]" : "";
        printf("║  %s │ %3llu/%3llu M   │  %10llu  │  %10llu  │  %10llu  │  %10llu  ║ %5.0f%s\n",
            class_names[i], rates[i], ceils[i],
            s[i].packets, s[i].borrowed, s[i].ecn_marked, s[i].delayed,
            mbps, mode);
    }

    printf("╠════════════════╪═════════════╪══════════════╪══════════════╪══════════════╪══════════════╣\n");
    printf("║  TOTAL          │             │  %10llu  │  %10llu  │  %10llu  │  %10llu  ║\n",
        tp, tb, te, td);
    printf("╚═══════════════════════════════════════════════════════════════════════════════════════════╝\n");
    printf("\n  EF = passthrough (no limit) | AF/BE: ECN for TCP, EDT delay for over-ceil\n");
    printf("  Pool: link=%llu Mbps | Press Ctrl+C to stop\n",
        (LINK_CAPACITY_BPS * 8) / 1000000);
    printf("  Mbit/s shows per-second delta\n");

    memcpy(prev, s, sizeof(prev));
}

int main(int argc, char **argv)
{
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <iface> [direction] [ef_rate ef_ceil af_rate af_ceil be_rate be_ceil]\n", argv[0]);
        fprintf(stderr, "Example: %s ens19 egress 500 800 300 500 200 300\n", argv[0]);
        fprintf(stderr, "  rate = guaranteed Mbps, ceil = max Mbps (with borrowing)\n");
        return 1;
    }

    const char *ifname = argv[1];
    const char *obj_path = "src/classifier.bpf.o";

    const char *direction = "egress";
    int arg_start = 2;
    if (argc > 2 && (strcmp(argv[2], "ingress") == 0 || strcmp(argv[2], "egress") == 0)) {
        direction = argv[2];
        arg_start = 3;
    }

    /* Parse: rate ceil for each class (default: 500/800 300/500 200/300) */
    __u64 rates[TC_MAX], ceils[TC_MAX];
    rates[TC_EF] = argc > arg_start     ? atoi(argv[arg_start])     : 500;
    ceils[TC_EF] = argc > arg_start + 1 ? atoi(argv[arg_start + 1]) : 800;
    rates[TC_AF] = argc > arg_start + 2 ? atoi(argv[arg_start + 2]) : 300;
    ceils[TC_AF] = argc > arg_start + 3 ? atoi(argv[arg_start + 3]) : 500;
    rates[TC_BE] = argc > arg_start + 4 ? atoi(argv[arg_start + 4]) : 200;
    ceils[TC_BE] = argc > arg_start + 5 ? atoi(argv[arg_start + 5]) : 300;

    if (if_nametoindex(ifname) == 0) {
        fprintf(stderr, "ERROR: Interface '%s' not found\n", ifname);
        return 1;
    }

    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    printf("\n");
    printf("  ╔══════════════════════════════════════════════╗\n");
    printf("  ║  eBPF QoS — Phase 3: Shaping + Borrowing    ║\n");
    printf("  ╠══════════════════════════════════════════════╣\n");
    printf("  ║  Interface:  %-30s  ║\n", ifname);
    printf("  ║  Direction:  %-30s  ║\n", direction);
    printf("  ║  EF:  rate=%-4llu ceil=%-4llu Mbps            ║\n", rates[TC_EF], ceils[TC_EF]);
    printf("  ║  AF:  rate=%-4llu ceil=%-4llu Mbps            ║\n", rates[TC_AF], ceils[TC_AF]);
    printf("  ║  BE:  rate=%-4llu ceil=%-4llu Mbps            ║\n", rates[TC_BE], ceils[TC_BE]);
    printf("  ╚══════════════════════════════════════════════╝\n\n");

    /* Setup: FQ root + clsact + eBPF */
    if (tc_setup(ifname, obj_path, direction) != 0)
        return 1;

    sleep(1);

    /* Find maps */
    int stats_fd  = find_map_fd("stats_map",  BPF_MAP_TYPE_ARRAY, TC_MAX);
    int config_fd = find_map_fd("config_map", BPF_MAP_TYPE_ARRAY, TC_MAX);

    if (stats_fd < 0 || config_fd < 0) {
        fprintf(stderr, "ERROR: Maps not found (stats=%d config=%d)\n",
                stats_fd, config_fd);
        tc_cleanup(ifname);
        return 1;
    }

    /* Set rate/ceil configs */
    set_class_config(config_fd, TC_EF, rates[TC_EF], ceils[TC_EF]);
    set_class_config(config_fd, TC_AF, rates[TC_AF], ceils[TC_AF]);
    set_class_config(config_fd, TC_BE, rates[TC_BE], ceils[TC_BE]);

    printf("  ✓ Configs set | Maps found\n");
    printf("  Monitoring... (Ctrl+C to stop)\n\n");
    sleep(1);

    while (running) {
        print_stats(stats_fd, rates, ceils);
        sleep(1);
    }

    close(stats_fd);
    close(config_fd);
    tc_cleanup(ifname);
    return 0;
}
