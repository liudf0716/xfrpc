![xfrp](https://github.com/KunTengRom/xfrp/blob/master/logo.png)

[![Build Status][1]][2]

[1]: https://travis-ci.org/KunTengRom/xfrp.svg?branch=master
[2]: https://travis-ci.org/KunTengRom/xfrp

## what is xfrp and why start xfrp

xfrp was [frp](https://github.com/fatedier/frp) client implemented by c for OpenWRT system

if you dont know what is frp, please visit [this](https://github.com/fatedier/frp)

the motivation to start xfrp project is that we are OpenWRTer, and openwrt usually ran in wireless router which has little ROM and RAM space, however golang always need more space and memory; therefore we start xfrp project

## compile

xfrp need [libevent](https://github.com/libevent/libevent) [openssl-dev](https://github.com/openssl/openssl) and [json-c](https://github.com/json-c/json-c) support

before compile xfrp, please install `libevent` `openssl-dev` and `json-c` in your system

git clone https://github.com/KunTengRom/xfrp.git

```shell
cd xfrp

cmake .

make
```

## quick start


run in debug mode :

```shell
xfrp_client -c frpc_mini.ini -f -d 7 
```

run in release mode :

```shell
xfrp_client -c frpc_mini.ini -d 0
```



## todo list

- support compression

- support encrypt

- support previlege mode


## how to contribute our project

See [CONTRIBUTING](https://github.com/KunTengRom/xfrp/blob/master/CONTRIBUTING.md) for details on submitting patches and the contribution workflow.

## Contact

QQ群 ： [331230369](https://jq.qq.com/?_wv=1027&k=47QGEhL)


## Please support us and star our project
