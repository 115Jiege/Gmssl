## About GmSSL
基于GmSSL1.0做出改进，按照标准文档`GMT 0003.2-2012 SM2椭圆曲线公钥密码算法第2部分：数字签名算法.pdf`修改了SM2签名算法。

## Quick Start

 ### Linux平台安装:

 ```sh
 ./config --prefix=/usr/local --openssldir=/usr/local
 #修改Makefile第36行为：INSTALL_SHLIB_INFO="libcrypto.so.$(SHLIB_MAJOR).$(SHLIB_MINOR);libgmcrypto.so" "libssl.so.$(SHLIB_MAJOR).$(SHLIB_MINOR);libssl.so"
make && make install
ldconfig
 ```

查看GmSSL版本

 ```sh
 gmssl version -a
 ```


### Windows平台安装（perl + vs2019）：

以管理员身份运行`x86 Native Tools Command Prompt for VS 2019`
cd gmssl目录
运行以下命令：

 ```sh
perl Configure VC-WIN32
nmake 
nmake install
 ```
 
### Android版安装
环境:ubuntu 20.04
选择需求版本安装
```sh
cd build-android
chmod a+x build-androidx86.sh
./build-androidx86.sh
chmod a+x build-androidx86_64.sh
./build-androidx86_64.sh
chmod a+x build-armv8.sh
./build-armv8.sh
chmod a+x build-armv7.sh
./build-armv7.sh
readelf -h ../libcrypto.so.1.1 #查看生成的so文件的系统架构等信息
```