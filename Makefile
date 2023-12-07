CFLAGS = -O3 -march=native -Wall
CC=gcc

all: cpu gpu
simple: target/simple
simd: target/mmx target/sse target/avx
cpu: simple simd
gpu: target/gpu

target:
	@mkdir -p $@

target/simple: cpu/simple.c target
	@$(CC) $< $(CFLAGS) -o $@

target/mmx: cpu/simd.c target
	@$(CC) $< -D SIMD_MMX $(CFLAGS) -o $@

target/sse: cpu/simd.c target
	@$(CC) $< -D SIMD_SSE $(CFLAGS) -o $@

target/avx: cpu/simd.c target
	@$(CC) $< -D SIMD_AVX $(CFLAGS) -o $@

target/gpu: gpu/main.c gpu/kernel.cl target
	@clang-15 --std=cl2.0 -S -emit-llvm -o /dev/null \
		 -Xclang -finclude-default-header gpu/kernel.cl \
	 && $(CC) -Wall -Igpu-opencl -o $@ -Wall gpu/main.c -l OpenCL

clean:
	@rm -rf target