#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/in.h>

SEC("xdp")
int packet_monitor(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    // Parse Ethernet header
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    // Extract MAC addresses
    __u16 src_mac1 = (__u16)(eth->h_source[0] << 8 | eth->h_source[1]);
    __u32 src_mac2 = (__u32)(eth->h_source[2] << 24 | eth->h_source[3] << 16 |
                             eth->h_source[4] << 8 | eth->h_source[5]);
    __u16 dest_mac1 = (__u16)(eth->h_dest[0] << 8 | eth->h_dest[1]);
    __u32 dest_mac2 = (__u32)(eth->h_dest[2] << 24 | eth->h_dest[3] << 16 |
                              eth->h_dest[4] << 8 | eth->h_dest[5]);

    // Print MAC addresses
    bpf_printk("Src MAC: %04x%08x", src_mac1, src_mac2);
    bpf_printk("Dest MAC: %04x%08x", dest_mac1, dest_mac2);

    // Only process IPv4 packets
    if (bpf_ntohs(eth->h_proto) != ETH_P_IP)
        return XDP_PASS;

    // Parse IP header
    struct iphdr *iph = (void *)(eth + 1);
    if ((void *)(iph + 1) > data_end)
        return XDP_PASS;

    // Extract source and destination IPs
    __u32 src_ip = bpf_ntohl(iph->saddr);
    __u32 dest_ip = bpf_ntohl(iph->daddr);

    __u8 src_ip_1 = (src_ip >> 24) & 0xFF;
    __u8 src_ip_2 = (src_ip >> 16) & 0xFF;
    __u8 src_ip_3 = (src_ip >> 8) & 0xFF;
    __u8 src_ip_4 = src_ip & 0xFF;

    __u8 dest_ip_1 = (dest_ip >> 24) & 0xFF;
    __u8 dest_ip_2 = (dest_ip >> 16) & 0xFF;
    __u8 dest_ip_3 = (dest_ip >> 8) & 0xFF;
    __u8 dest_ip_4 = dest_ip & 0xFF;

    // Print IP addresses
    bpf_printk("Src IP: %d.%d.", src_ip_1, src_ip_2);
    bpf_printk("      : %d.%d", src_ip_3, src_ip_4);

    bpf_printk("Dest IP: %d.%d.", dest_ip_1, dest_ip_2);
    bpf_printk("       : %d.%d", dest_ip_3, dest_ip_4);

    // Identify protocol and print ports if applicable
    if (iph->protocol == IPPROTO_TCP) {
        struct tcphdr *tcph = (void *)(iph + 1);
        if ((void *)(tcph + 1) > data_end)
            return XDP_PASS;
        bpf_printk("Protocol: TCP");
        bpf_printk("Src Port: %d", bpf_ntohs(tcph->source));
        bpf_printk("Dest Port: %d", bpf_ntohs(tcph->dest));
    } else if (iph->protocol == IPPROTO_UDP) {
        struct udphdr *udph = (void *)(iph + 1);
        if ((void *)(udph + 1) > data_end)
            return XDP_PASS;
        bpf_printk("Protocol: UDP");
        bpf_printk("Src Port: %d", bpf_ntohs(udph->source));
        bpf_printk("Dest Port: %d", bpf_ntohs(udph->dest));
    } else {
        bpf_printk("Other Protocol: %d", iph->protocol);
    }

    // Calculate and print packet length
    __u64 packet_len = (void *)data_end - (void *)data;
    bpf_printk("Packet Length: %llu bytes", packet_len);

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
