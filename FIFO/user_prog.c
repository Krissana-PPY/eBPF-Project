#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <net/if.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <linux/if_link.h>
#include <sys/resource.h>

// ตรงกับ eBPF struct
struct pkt_fifo_meta {
    __u64 pkt_len;
    __u64 timestamp;
    __u64 sequence;
};

static void handle_event(void *ctx, int cpu, void *data, __u32 data_sz) {
    struct pkt_fifo_meta *pkt = data;
    printf("seq=%llu len=%llu ts=%llu\n",
        pkt->sequence,
        pkt->pkt_len,
        pkt->timestamp
    );
}

int main(int argc, char **argv) {
    struct perf_buffer *pb = NULL;
    struct bpf_object *obj = NULL;
    struct bpf_program *prog;
    int prog_fd;
    int ifindex;

    if (argc < 2) {
        fprintf(stderr, "Usage: %s <iface>\n", argv[0]);
        return 1;
    }

    struct rlimit r = {RLIM_INFINITY, RLIM_INFINITY};
    setrlimit(RLIMIT_MEMLOCK, &r);

    obj = bpf_object__open_file("xdp_Q.o", NULL);
    if (!obj) {
        fprintf(stderr, "Error opening BPF object file: %s\n", strerror(errno));
        return 1;
    }

    if (bpf_object__load(obj)) {
        fprintf(stderr, "Error loading BPF object: %s\n", strerror(errno));
        bpf_object__close(obj);
        return 1;
    }

    prog = bpf_object__next_program(obj, NULL);
    if (!prog) {
        fprintf(stderr, "No program found in BPF object\n");
        bpf_object__close(obj);
        return 1;
    }
    prog_fd = bpf_program__fd(prog);

    ifindex = if_nametoindex(argv[1]);
    if (ifindex == 0) {
        perror("if_nametoindex");
        bpf_object__close(obj);
        return 1;
    }
    if (bpf_xdp_attach(ifindex, prog_fd, XDP_FLAGS_DRV_MODE, NULL) < 0) {
        perror("bpf_xdp_attach");
        fprintf(stderr, "Fallback to generic/skb mode\n");
        if (bpf_xdp_attach(ifindex, prog_fd, XDP_FLAGS_SKB_MODE, NULL) < 0) {
            perror("bpf_xdp_attach (SKB mode)");
            bpf_object__close(obj);
            return 1;
        }
    }

    int map_fd = bpf_map__fd(bpf_object__find_map_by_name(obj, "events"));
    if (map_fd < 0) {
        fprintf(stderr, "Failed to get map fd: %s\n", strerror(errno));
        bpf_xdp_detach(ifindex, XDP_FLAGS_MASK, NULL);
        bpf_object__close(obj);
        return 1;
    }

    struct perf_buffer_opts pb_opts = {};
    pb_opts.sz = sizeof(struct perf_buffer_opts);
    pb = perf_buffer__new(map_fd, 8, handle_event, NULL, NULL, &pb_opts);
    if (!pb) {
        fprintf(stderr, "Failed to open perf buffer: %s\n", strerror(errno));
        bpf_xdp_detach(ifindex, XDP_FLAGS_MASK, NULL);
        bpf_object__close(obj);
        return 1;
    }

    printf("Listening for packets on interface %s...\n", argv[1]);
    while (1) {
        int err = perf_buffer__poll(pb, 100);
        if (err < 0 && err != -EINTR) {
            fprintf(stderr, "Error polling perf buffer: %s\n", strerror(-err));
            break;
        }
    }

    perf_buffer__free(pb);
    bpf_xdp_detach(ifindex, XDP_FLAGS_MASK, NULL);
    bpf_object__close(obj);
    return 0;
}