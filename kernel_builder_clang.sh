#!/bin/bash

# shitty kernel reeeee

#PREFIX="$(pwd)"
PREFIX="/tmp/tc"

#CLANG="greenforce"
CLANG="zyc"

KSUVER="11657"

if [ ! -d "KernelSU" ]; then
  git clone https://github.com/backslashxx/KernelSU -b $KSUVER
fi



#rm -rf out
#mkdir out
#rm -rf error.log
#make O=out clean 
#make mrproper

# Build

CLANG_DIR=${PREFIX}/${CLANG}
export PATH="$CLANG_DIR/bin:$PATH"

echo $PATH

make O=out ARCH=arm64 ../../../fog-perf_defconfig

make -j24 ARCH=arm64 SUBARCH=arm64 O=out \
        CC="ccache clang --target=aarch64 -march=armv8-a+crc+crypto -mcpu=cortex-a73+crc+crypto -mtune=cortex-a73 -funroll-loops -O3"\
        AR="llvm-ar" \
	NM="llvm-nm" \
	LD="ld.lld" \
	OBJCOPY="llvm-objcopy" \
	OBJDUMP="llvm-objdump" \
	STRIP="llvm-strip" \
        CLANG_TRIPLE="aarch64-linux-gnu-" \
    	CROSS_COMPILE="aarch64-linux-gnu-" \
    	CROSS_COMPILE_ARM32="arm-linux-gnueabi-" \
    	CROSS_COMPILE_COMPAT="arm-linux-gnueabi-" \
    	LLVM=1 \
    	LLVM_IAS=1 \
    	INSTALL_MOD_STRIP=1 \
	KBUILD_BUILD_USER="$(git rev-parse --short HEAD | cut -c1-7)" \
	KBUILD_BUILD_HOST="$(git symbolic-ref --short HEAD)" \
	KBUILD_BUILD_FEATURES="ksu: $KSUVER /"
	
	
ccache -s

echo "ksu: $KSUVER"


# fp asimd evtstrm aes pmull sha1 sha2 crc32 atomics fphp asimdhp cpuid asimdrdm lrcpc dcpop asimddp
# for i in $(ls patches/) ; do patch -Np1 < patches/$i ; done
