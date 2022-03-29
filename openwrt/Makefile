#
# Copyright (C) 2022 Dengfeng Liu
#
# This is free software, licensed under the GNU General Public License v3.
# See /LICENSE for more information.
#

include $(TOPDIR)/rules.mk

PKG_NAME:=xfrpc
PKG_VERSION:=0.07.496
PKG_RELEASE:=1

PKG_SOURCE_PROTO:=git
PKG_SOURCE_URL:=https://github.com/liudf0716/xfrpc.git
PKG_SOURCE_VERSION:=$(PKG_VERSION)
PKG_MIRROR_HASH:=0fadb7a0e139bf4a5c6daffdd0f200ee2a4c903aea71e46bc19212b054ca71a7

PKG_MAINTAINER:=Dengfeng Liu <liudf0716@gmail.com>
PKG_LICENSE:=GPL-3.0-or-later
PKG_LICENSE_FILES:=COPYING

include $(INCLUDE_DIR)/package.mk
include $(INCLUDE_DIR)/cmake.mk

define Package/xfrpc
  SUBMENU:=Web Servers/Proxies
  SECTION:=net
  CATEGORY:=Network
  DEPENDS:=+libjson-c +libevent2
  TITLE:= C language fast reverse proxy client
  URL:=https://github.com/liudf0716/xfrpc
endef

define Package/xfrpc/description
  xfrpc is C language fast reverse proxy client
  compare with golang version frpc
  xfrpc can run in almost all openwrt device
endef

define Package/xfrpc/conffiles
/etc/config/xfrpc
endef

define Package/xfrpc/install
        $(INSTALL_DIR) $(1)/usr/bin
        $(INSTALL_BIN) $(PKG_INSTALL_DIR)/usr/bin/wifidogx $(1)/usr/bin/wifidogx
        $(INSTALL_BIN) $(PKG_INSTALL_DIR)/usr/bin/wdctlx $(1)/usr/bin/wdctlx
        $(INSTALL_DIR) $(1)/etc/init.d
        $(INSTALL_BIN) ./files/xfrpc.init $(1)/etc/init.d/xfrpc
        $(INSTALL_DIR) $(1)/etc/config
        $(CP) ./files/xfrpc.conf $(1)/etc/config/xfrpc
 endef

$(eval $(call BuildPackage,xfrpc))                                                                                                                                                                                                                                                         1,1           Top
