# MD4 Bruteforce

This project is a proof of concept of bruteforcing md4 digest produced by passwords having lenght between 3 and 7 characters.

The characters used in password must be in the following list: `abcdefghikjlmnopqrstuvwxyz!"#$%&`

MD4 implementation has been optimized to have a maximum of performance for this special case.

This project provides CPU based implementations and a GPU based implementation using OpenCL.

Please note that CPU based implementations will only work on little endian CPU due to the nature of optimizations used.

On GPU implementation, the two first characters of the password must use only alphabet characters: `!"#$%&` are excluded.

This project use the C programming language.

## Compiling project

To compile only cpu implementation you will need only `make` and `gcc` to be installed.

You can choose different target when running the makefile:

- `simple` will build only a generic implementation of MD4 (works on different architecture)
- `simd` will build different executable using intel intrisincts functions: you need to have a compatible CPU (architecture intel/amd x86_64 -> it will not run on ARM cpu).
- `cpu` will build both `simple` and `simd` implementations
- `gpu` will build openCL based implementation
- `all` will build both  `cpu` and `gpu` implementations

`simd` rule will produce several executables:

- mmx uses a 64 bits vector and computes 2 digests at the same time
- sse uses a 128 bits vector and computes 4 digests at the same time
- avx uses a 256 bits vector and computes 8 digests at the same time

 "avx512" is not supported.

To build `gpu` implementation you will need to install additional packages. It may change depending on your distro.

On Debian:

```
apt-get install nvidia-driver
apt install clang-15 opencl-c-headers clinfo nvidia-libopencl1
clinfo
```


## Usage

Once you have sucessfully compiled one implementation, you shoud find the executable in a newly created `target` folder.

### 1) CPU

To test CPU based implementation:

`./target/simple <md4 digest>` or `./target/sse <md4 digest>` ...

It should display the number of password tried each second while running. 

To give you an idea of what kind of speed to expect, here is a summary of tests on different benchmarks:

- using `simple` implementation, it computes 7.6M digests/s on an ARM cortex A72, 21M/s on my school computer (intel i5, 5th generation), 38.4M/s on a Ryzen 7 7700x.
- using `sse` implementation, 60M/s on my school computer (intel i5, 5th generation), 117.4M/s on a Ryzen 7 7700x.
- using `avx` implementation, 115M/s on my school computer (intel i5, 5th generation), 236M/s on a Ryzen 7 7700x.

### 2) GPU

To run GPU implementation, you must pass an additional argument (the openCL kernel path):

`./target/gpu gpu/kernel.cl <md4 digest>`

GPU implemention should have more performance than CPU implementation. (It depends on your hardware)

## Project organization

Project is divided in different folder:

- "cpu" folder contains simple and simd implementation. "mmx","sse" and "avx" executable are built from the same file `cpu/simd.c`. We choose the type of target to build at compilation time using compiler flags.
- "gpu" folder contains OpenCL kernel and implementation in c for gpu.
- "include" contains common headers used by different implementations

**If you want to change the length of the password bruteforced, you must edit "*include/config.h*" file and change "*PWD_LEN*" value. The value is applied to each implementation at compilation time.**

Executable can be found in the "target" folder.
