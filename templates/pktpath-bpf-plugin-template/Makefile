CLANG ?= clang
BPF_CFLAGS ?= -O2 -g -target bpf

.PHONY: all arm64 x86_64 keygen pack clean

all: arm64

arm64:
	mkdir -p bpf/arm64
	$(CLANG) $(BPF_CFLAGS) -D__TARGET_ARCH_arm64 -c bpf/example_probe.bpf.c -o bpf/arm64/example_probe.bpf.o

x86_64:
	mkdir -p bpf/x86_64
	$(CLANG) $(BPF_CFLAGS) -D__TARGET_ARCH_x86 -c bpf/example_probe.bpf.c -o bpf/x86_64/example_probe.bpf.o

keygen:
	node scripts/sign-and-pack.mjs keygen --out-dir ./keys

pack:
	node scripts/sign-and-pack.mjs pack --dir . --out ./dist/example-bpf-plugin.zip

clean:
	rm -rf bpf/arm64 bpf/x86_64 dist signature.json
