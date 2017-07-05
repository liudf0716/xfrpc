![xfrp](https://github.com/KunTengRom/xfrp/blob/master/logo.png)

[![Build Status][1]][2]
[![license][3]][4]
[![Supported][7]][8]
[![PRs Welcome][5]][6]
[![Issue Welcome][9]][10]
[![OpenWRT][11]][12]
[![KunTeng][13]][14]

[1]: https://img.shields.io/travis/KunTengRom/xfrp.svg?style=plastic
[2]: https://travis-ci.org/KunTengRom/xfrp
[3]: https://img.shields.io/badge/license-GPLV3-brightgreen.svg?style=plastic
[4]: https://github.com/KunTengRom/xfrp/blob/master/LICENSE
[5]: https://img.shields.io/badge/PRs-welcome-brightgreen.svg?style=plastic
[6]: https://github.com/KunTengRom/xfrp/pulls
[7]: https://img.shields.io/badge/XFRPS-Supported-blue.svg?style=plastic
[8]: https://github.com/KunTengRom/xfrps
[9]: https://img.shields.io/badge/Issues-welcome-brightgreen.svg?style=plastic
[10]: https://github.com/KunTengRom/xfrp/issues/new
[11]: https://img.shields.io/badge/Platform-%20OpenWRT%20%7CLEDE%20-brightgreen.svg?style=plastic
[12]: https://github.com/KunTengRom/LEDE
[13]: https://img.shields.io/badge/KunTeng-Inside-blue.svg?style=plastic
[14]: http://rom.kunteng.org

## What is xfrp and why start xfrp

xfrp was [xfrps](https://github.com/KunTengRom/xfrp) client implemented by c for OpenWRT system

The motivation to start xfrp project is that we are OpenWRTer, and openwrt usually ran in device which has little ROM and RAM space, however golang always need more space and memory; therefore we start xfrp project

## Compile

xfrp need [libevent](https://github.com/libevent/libevent) [openssl-dev](https://github.com/openssl/openssl) and [json-c](https://github.com/json-c/json-c) support

Before compile xfrp, please install `libevent` `openssl-dev` and `json-c` in your system.

```shell
git clone https://github.com/KunTengRom/xfrp.git
cd xfrp
cmake .
make
```

## Quick start


Run in debug mode :

```shell
xfrpc -c frpc_mini.ini -f -d 7 
```

Run in release mode :

```shell
xfrpc -c frpc_mini.ini -d 0
```

----

## Todo list

- support compression
- support encrypt


## How to contribute our project

See [CONTRIBUTING](https://github.com/KunTengRom/xfrp/blob/master/CONTRIBUTING.md) for details on submitting patches and the contribution workflow.

## Contact

QQ群 ： [331230369](https://jq.qq.com/?_wv=1027&k=47QGEhL)


## Please support us and star our project
