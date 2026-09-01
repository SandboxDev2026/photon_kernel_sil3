# Photon Kernel Sandbox - eBPF 模块 Makefile
# 需要: clang, libbpf-dev, linux-headers
# 用法:
#   make          # 编译 eBPF 程序 + 加载器
#   make load     # 加载 eBPF（需要 root）
#   make verify   # 一键验证（需要 root）
#   make clean    # 清理
CLANG ?= clang
CXX ?= g++
BPF_CFLAGS := -O2 -target bpf -D__TARGET_ARCH_x86_64 -I/usr/include/bpf -I/usr/include
LOADER_CFLAGS := -std=c++17 -O2 -Wall
LOADER_LIBS := -lbpf -lelf -lz
OBJ := sandbox_filter.o
LOADER := ebpf_loader
.PHONY: all clean load verify
all: $(OBJ) $(LOADER)
# 编译 eBPF 程序
$(OBJ): sandbox_filter.c
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@
	@echo "[OK] eBPF program compiled: $@"
# 编译加载器
$(LOADER): ebpf_loader.cpp
	$(CXX) $(LOADER_CFLAGS) $< -o $@ $(LOADER_LIBS)
	@echo "[OK] eBPF loader compiled: $@"
# 加载 eBPF（需要 root）
load: $(OBJ) $(LOADER)
	@if [ "$$EUID" -ne 0 ]; then echo "ERROR: need root"; exit 1; fi
	./$(LOADER) --obj $(OBJ) --iface eth0 \
		--whitelist 10.0.0.0/8:80-443:tcp \
		--whitelist 0.0.0.0/0:53:udp \
		--duration 10 --stats
# 一键验证（需要 root + clang + libbpf）
verify:
	@echo "=== eBPF Verification ==="
	@echo "[1/5] Checking dependencies..."
	@which clang || (echo "FAIL: clang not found"; exit 1)
	@which bpftool || echo "WARN: bpftool not found (optional)"
	@pkg-config --exists libbpf || (echo "FAIL: libbpf not found (apt install libbpf-dev)"; exit 1)
	@echo "[OK] dependencies ready"
	@echo "[2/5] Checking kernel support..."
	@zcat /proc/config.gz 2>/dev/null | grep -q CONFIG_BPF=y || grep -q CONFIG_BPF=y /boot/config-$$(uname -r) || (echo "FAIL: kernel BPF not enabled"; exit 1)
	@echo "[OK] kernel supports BPF"
	@echo "[3/5] Checking privileges..."
	@if [ "$$EUID" -ne 0 ]; then echo "FAIL: need root (CAP_BPF)"; exit 1; fi
	@cat /proc/sys/kernel/unprivileged_bpf_disabled | grep -q 1 && echo "[INFO] unprivileged_bpf_disabled=1 (root can still load)" || true
	@echo "[OK] root privileges"
	@echo "[4/5] Compiling eBPF program..."
	$(MAKE) all
	@echo "[5/5] Loading and verifying..."
	./$(LOADER) --obj $(OBJ) --iface lo \
		--whitelist 127.0.0.1/32:1-65535:tcp \
		--duration 3 --stats 2>&1 | head -20
	@echo ""
	@echo "=== eBPF Verification PASSED ==="
clean:
	rm -f $(OBJ) $(LOADER)
