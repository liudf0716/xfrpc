#
# Copyright (C) 2022 Dengfeng Liu
#
# This is free software, licensed under the GNU General Public License v3.
# See /LICENSE for more information.
#

include $(TOPDIR)/rules.mk

PKG_NAME:=xfrpc
#PKG_VERSION:=0.07.496
PKG_VERSION:=master
PKG_RELEASE:=1

PKG_SOURCE_PROTO:=git
PKG_SOURCE_URL:=https://github.com/liudf0716/xfrpc.git
PKG_SOURCE_VERSION:=$(PKG_VERSION)
PKG_MIRROR_HASH:=a7141da8a85203d8341fd6d2551f1228396ae54aace6ec0bad2dfeb89e0a377d

PKG_MAINTAINER:=Dengfeng Liu <liudf0716@gmail.com>
PKG_LICENSE:=GPL-3.0-or-later
PKG_LICENSE_FILES:=COPYING

include $(INCLUDE_DIR)/package.mk
include $(INCLUDE_DIR)/cmake.mk

define Package/xfrpc
  SUBMENU:=Web Servers/Proxies
  SECTION:=net
  CATEGORY:=Network
  DEPENDS:=+zlib +libjson-c +libevent2 +libevent2-openssl
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
        $(INSTALL_BIN) $(PKG_INSTALL_DIR)/usr/bin/xfrpc $(1)/usr/bin/xfrpc
        $(INSTALL_DIR) $(1)/etc/init.d
        $(INSTALL_BIN) ./files/xfrpc.init $(1)/etc/init.d/xfrpc
        $(INSTALL_DIR) $(1)/etc/config
        $(CP) ./files/xfrpc.conf $(1)/etc/config/xfrpc
endef

$(eval $(call BuildPackage,xfrpc))
