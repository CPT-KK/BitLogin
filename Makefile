# For Openwrt build only
# For building on normal system, use CMake

include $(TOPDIR)/rules.mk

PKG_NAME:=BitLogin
PKG_VERSION:=0.12.0
PKG_RELEASE:=1

PKG_BUILD_DIR:=$(BUILD_DIR)/BitLogin-$(PKG_VERSION)

include $(INCLUDE_DIR)/package.mk
include $(INCLUDE_DIR)/cmake.mk

define Package/BitLogin
	CATEGORY:=Network
	TITLE:=BitLogin
	DEPENDS:=+libstdcpp
endef

define Package/BitLogin/description
	BitLogin is a simple C++ implementation of BIT Srun login/logout client.
endef

define Build/Prepare
	mkdir -p $(PKG_BUILD_DIR)
	$(CP) ./* $(PKG_BUILD_DIR)/
endef

define Package/BitLogin/install	
	$(INSTALL_DIR) $(1)/usr/bin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/BitLogin $(1)/usr/bin/
endef

$(eval $(call BuildPackage,BitLogin))
