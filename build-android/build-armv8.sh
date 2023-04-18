#!/bin/bash
 
ANDROID_PATH=$ANDROID_NDK_PATH
PLATFORM_VERSION=21
 
MAKE_TOOLCHAIN=$ANDROID_PATH/build/tools/make-standalone-toolchain.sh
export TOOLCHAIN_PATH=$ANDROID_PATH/aarch64-linux-android
$MAKE_TOOLCHAIN --arch=arm64 --platform=android-$PLATFORM_VERSION --install-dir=$TOOLCHAIN_PATH

export CROSS_SYSROOT=$TOOLCHAIN_PATH/sysroot
export TOOL_BASENAME=$TOOLCHAIN_PATH/bin
export PATH=$CROSS_SYSROOT:$PATH
export PATH=$TOOL_BASENAME:$PATH
 
../Configure --prefix=/usr/local --cross-compile-prefix=aarch64-linux-android- no-asm no-async shared android64-aarch64
make && make install