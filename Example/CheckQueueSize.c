
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/pkt_cls.h>
#include <linux/types.h> // Include for __u32 type

// Define a BPF map to hold the queue size
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32); // Use __u32 for key
    __type(value, __u32); // Use __u32 for value
} queue_size_map SEC(".maps");

// Function to update the queue size
static inline void update_queue_size(__u32 size) {
    __u32 key = 0; // Key for the map
    bpf_map_update_elem(&queue_size_map, &key, &size, BPF_ANY);
}

// XDP program to check the queue size
SEC("xdp")
int check_queue_size(struct __sk_buff *skb) {
    __u32 key = 0; // Key for the map
    __u32 *queue_size; // Pointer to hold the queue size

    // Lookup the current queue size in the map
    queue_size = bpf_map_lookup_elem(&queue_size_map, &key);
    if (!queue_size) {
        return XDP_DROP; // Drop the packet if queue size not found
    }

    // Print the current queue size for debugging
    bpf_printk("Current queue size: %d\n", *queue_size);

    // Update the queue size based on your logic (e.g., increment it)
    __u32 new_size = *queue_size + 1; // Example: increment queue size
    update_queue_size(new_size); // Update the map with the new size

    // Return the current queue size
    return XDP_PASS;
}

// License declaration
char _license[] SEC("license") = "GPL";
