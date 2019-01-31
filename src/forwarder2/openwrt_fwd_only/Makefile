# Kernel module example
include $(TOPDIR)/rules.mk
include $(INCLUDE_DIR)/kernel.mk

PKG_NAME:=Forwarder
PKG_RELEASE:=1

include $(INCLUDE_DIR)/package.mk

define KernelPackage/forwarder
	SUBMENU:=Other modules
	# DEPENDS:=@TARGET_octeon
	TITLE:=Forwarder conponent 2
	MENU:=1
	# AUTOLOAD:=$(call AutoLoad,81,example)
	FILES:=$(PKG_BUILD_DIR).$(LINUX_KMOD_SUFFIX)
endef

define Build/Prepare
	mkdir -p $(PKG_BUILD_DIR)
	$(CP) -R ./src/* $(PKG_BUILD_DIR)/
endef

define Build/Compile
	$(MAKE) -C "$(LINUX_DIR)" \
	CROSS_COMPILE="$(TARGET_CROSS)" \
	ARCH="$(LINUX_KARCH)" \
	SUBDIRS="$(PKG_BUILD_DIR)" \
	EXTRA_CFLAGS="-g $(BUILDFLAGS)" \
	modules
endef

$(eval $(call KernelPackage,forwarder))
 
