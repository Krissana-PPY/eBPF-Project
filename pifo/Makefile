CLANG ?= clang          # ใช้ clang สำหรับคอมไพล์โปรแกรม C หรือ BPF
LLC ?= llc              # สำหรับใช้ llc ในการแปลงเป็น BPF IR (ถ้าจำเป็น)
CFLAGS = -Wall -O2 -g    # ตัวเลือกคอมไพล์เบื้องต้น: -Wall (เตือนทั้งหมด), -O2 (ระดับการโอปติมุม), -g (เพิ่มข้อมูล debug)

LIBS = -lbpf -lelf -lz   # ลิงก์กับไลบรารีที่ต้องการใช้: -lbpf (ไลบรารี BPF), -lelf (ไลบรารี ELF), -lz (ไลบรารี zlib)

# กำหนดพาธคอมไพล์สำหรับ BPF
BPF_CFLAGS = -g -O2 -target bpf -D__TARGET_ARCH_x86 \
    -I/usr/include \                                  # พาธสำหรับไฟล์ header ที่จำเป็น
    -I$(shell clang -print-resource-dir)/include \      # ใช้ clang สำหรับดึงพาธไฟล์ header
    -I./                                               # เพิ่มพาธปัจจุบัน (.) เพื่อให้สามารถเข้าถึงไฟล์ header ในโปรเจกต์

all: xdp_Q.o user_prog      # เมื่อเรียก make โดยไม่ระบุเป้าหมายใด ๆ จะคอมไพล์ xdp_pifo.o และ user_prog

# สำหรับคอมไพล์ไฟล์ xdp_pifo.c เป็นไฟล์ xdp_pifo.o
xdp_pifo.o: xdp_Q.c common.h
        $(CLANG) $(BPF_CFLAGS) -c xdp_Q.c -o xdp_Q.o  # ใช้ clang คอมไพล์ไฟล์ C (xdp_pifo.c) เป็นไฟล์ object (.o) ที่ใช้ใน BPF

# สำหรับคอมไพล์ไฟล์ user_prog.c เป็นไฟล์ที่สามารถรันได้ (user_prog)
user_prog: user_prog.c common.h
        $(CC) $(CFLAGS) user_prog.c -o user_prog $(LIBS)  # ใช้ตัวแปร CC (อาจเป็น gcc หรือ clang) คอมไพล์โปรแกรม user_prog.c และลิงก์กับไลบรารีที่กำหนดใน LIBS

# สำหรับลบไฟล์ที่คอมไพล์แล้ว (ทำความสะอาดโปรเจกต์)
clean:
        rm -f xdp_Q.o user_prog  # ลบไฟล์ที่คอมไพล์แล้ว (ไฟล์ object .o และโปรแกรมที่คอมไพล์เสร็จแล้ว)