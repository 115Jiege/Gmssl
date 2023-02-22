## About GmSSL
基于GmSSL1.0做出改进，按照标准文档`GMT 0003.2-2012 SM2椭圆曲线公钥密码算法第2部分：数字签名算法.pdf`修改了SM2签名算法。

## Quick Start

 ### Linux平台安装:

 ```sh
 $ ./config --prefix=/usr/local/gmssl --openssldir=/usr/local/gmssl no-shared
 $ make
 ```

配置环境变量

 ```sh
vim ~/.bashrc
export PATH=$PATH:/usr/local/gmssl/bin
source ~/.bashrc
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