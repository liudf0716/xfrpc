![xfrp](https://github.com/KunTengRom/xfrp/blob/master/logo.png)


[![license][3]][4]
[![Build Status][1]][2] 
[![PRs Welcome][5]][6]

[1]: https://travis-ci.org/KunTengRom/xfrp.svg?branch=master
[2]: https://travis-ci.org/KunTengRom/xfrp
[3]: https://img.shields.io/badge/license-GPLV3-brightgreen.svg?style=flat
[4]: https://github.com/KunTengRom/xfrp/blob/master/LICENSE
[5]: https://img.shields.io/badge/PRs-welcome-brightgreen.svg
[6]: https://github.com/KunTengRom/xfrp/pulls

## What is xfrp and why start xfrp

xfrp was [frp](https://github.com/fatedier/frp) client implemented by c for OpenWRT system

If you dont know what is frp, please visit [this](https://github.com/fatedier/frp)

The motivation to start xfrp project is that we are OpenWRTer, and openwrt usually ran in wireless router which has little ROM and RAM space, however golang always need more space and memory; therefore we start xfrp project

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
xfrp_client -c frpc_mini.ini -f -d 7 
```

Run in release mode :

```shell
xfrp_client -c frpc_mini.ini -d 0
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
