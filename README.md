# eBPF Project
  ### ติดตั้งเครื่องมือที่จำเป็น
  ```sh
  sudo apt update
  sudo apt install -y clang llvm libelf-dev libpcap-dev gcc-multilib build-essential
  sudo apt install -y linux-tools-generic linux-tools-$(uname -r)
  sudo apt install -y bpfcc-tools libbpf-dev
  ```

  ### C source to bytecode
  ```sh
  sudo clang -target bpf -O2 -g -I/usr/include/$(uname -m)-linux-gnu -c filename.bpf.c -o filname.bpf.o
  ```

  ### นำ eBPF ไปไว้ยัง interface ที่ต้องการ
  ```sh
  sudo ip link set dev <interface> xdp obj filename.bpf.o sec xdp
  ```

  ### show list 
  ```sh
  sudo bpftool prog list
  ```

  ### show file in hook
  ```sh
  sudo bpftool net list
  ```

  ### Monitor eBPF
  ```sh
  sudo bpftool prog trace log
  ```

  ### ลบ eBPF ออกจากหน้า interface
  ```sh
  sudo bpftool net detach xdp  dev <interface>
  ```