CC ?= clang
CFLAGS ?= -O2 -g -Wall -Wextra

BPF_CLANG ?= clang
BPF_CFLAGS ?= -O2 -g -target bpf

# Override if needed (e.g. make TARGET_ARCH=arm64)
TARGET_ARCH ?= x86
BPF_ARCH_DEFINE := -D__TARGET_ARCH_$(TARGET_ARCH)

BPF_INCLUDES ?= -I/usr/include -I/usr/include/x86_64-linux-gnu

BPF_SRCS := \
	bpf/xdp_dispatcher.c \
	bpf/stage1_passthrough.c \
	bpf/stage2_video_filter.c
BPF_OBJS := $(BPF_SRCS:.c=.o)

.PHONY: all attach_ext bpf clean

all: attach_ext


attach_ext: attach_ext.c
	@echo "[build] $@"
	@pkg-config --exists libbpf 2>/dev/null && \
		$(CC) $(CFLAGS) -o $@ $< $$(pkg-config --cflags --libs libbpf) || \
		$(CC) $(CFLAGS) -o $@ $< -lbpf -lelf -lz

bpf: $(BPF_OBJS)

bpf/%.o: bpf/%.c
	@echo "[bpf] $@"
	$(BPF_CLANG) $(BPF_CFLAGS) $(BPF_ARCH_DEFINE) $(BPF_INCLUDES) -c $< -o $@

clean:
	@echo "[clean]"
	rm -f attach_ext
	rm -f $(BPF_OBJS)
