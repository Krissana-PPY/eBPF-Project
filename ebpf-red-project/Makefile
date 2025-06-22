CLANG=clang                # กำหนดตัวแปร CLANG ให้เป็น clang
CFLAGS=-O2 -g -Wall -target bpf   # กำหนด options สำหรับ clang เพื่อ compile เป็น bpf

BPF_OBJ_XDP=xdp_red_prog.o     # กำหนดชื่อไฟล์ object สำหรับ XDP
BPF_OBJ_KPROBE=kprobe_qdisc.o  # กำหนดชื่อไฟล์ object สำหรับ kprobe

all: $(BPF_OBJ_XDP) $(BPF_OBJ_KPROBE)  # เป้าหมาย all จะ build ทั้งสอง object

$(BPF_OBJ_XDP): xdp_red_logic.c red_map.h   # ถ้า xdp_red_prog.o ยังไม่มีหรือไฟล์ต้นทางเปลี่ยน
	$(CLANG) $(CFLAGS) -c xdp_red_logic.c -o $(BPF_OBJ_XDP)  # compile xdp_red_logic.c

$(BPF_OBJ_KPROBE): kprobe_qdisc.c red_map.h # ถ้า kprobe_qdisc.o ยังไม่มีหรือไฟล์ต้นทางเปลี่ยน
	$(CLANG) $(CFLAGS) -c kprobe_qdisc.c -o $(BPF_OBJ_KPROBE) # compile kprobe_qdisc.c

clean:      # เป้าหมาย clean สำหรับลบไฟล์ที่ build แล้ว
	rm -f *.o update_max_qlen   # ลบไฟล์ .o และ update_max_qlen
