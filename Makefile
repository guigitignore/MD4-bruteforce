CFLAGS = -O3 -march=native -Wall
CC=gcc

all: target target/simple target/mmx target/sse target/avx target/gpu

target:
	@mkdir -p $@

target/simple: cpu/simple.c
	@$(CC) $< $(CFLAGS) -o $@

target/mmx: cpu/simd.c
	@$(CC) $< -D SIMD_MMX $(CFLAGS) -o $@

target/sse: cpu/simd.c
	@$(CC) $< -D SIMD_SSE $(CFLAGS) -o $@

target/avx: cpu/simd.c
	@$(CC) $< -D SIMD_AVX $(CFLAGS) -o $@

target/gpu: gpu/main.c gpu/kernel.cl
	@clang-15 --std=cl2.0 -S -emit-llvm -o /dev/null \
		 -Xclang -finclude-default-header gpu/kernel.cl \
	 && $(CC) -Wall -Igpu-opencl -o $@ -Wall gpu/main.c -l OpenCL

clean:
	@rm -rf target