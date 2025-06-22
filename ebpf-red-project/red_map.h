// Map สำหรับระดับ RED (0 = Green, 1 = Yellow, 2 = Red)
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY); // กำหนดชนิด map เป็น array
    __uint(max_entries, 1); // มีได้ 1 entry
    __type(key, __u32); // key เป็นชนิด __u32
    __type(value, __u32); // value เป็นชนิด __u32
} red_state_map SEC(".maps"); // ประกาศชื่อ map และ section

// Map สำหรับ max queue length (เช่น 300)
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY); // กำหนดชนิด map เป็น array
    __uint(max_entries, 1); // มีได้ 1 entry
    __type(key, __u32); // key เป็นชนิด __u32
    __type(value, __u32); // value เป็นชนิด __u32
} max_qlen_map SEC(".maps"); // ประกาศชื่อ map และ section
