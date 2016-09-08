KBUILD_CFLAGS += -I$(src)
KERNEL_DIR ?= /lib/modules/$(shell uname -r)/build
PREFIX ?=

virtio-crypto-objs := virtio_crypto_algs.o virtio_crypto_mgr.o virtio_crypto.o
obj-m := virtio-crypto.o

KERNEL_MAKE_OPTS := -C ${KERNEL_DIR} SUBDIRS=`pwd`
ifneq (${ARCH},)
KERNEL_MAKE_OPTS += ARCH=${ARCH}
endif
ifneq (${CROSS_COMPILE},)
KERNEL_MAKE_OPTS += CROSS_COMPILE=${CROSS_COMPILE}
endif

build: version.h
	make ${KERNEL_MAKE_OPTS} modules

version.h: Makefile
	@echo "#define VERSION \"$(VERSION)\"" > version.h

install: modules_install

modules_install:
	make -C $(KERNEL_DIR) SUBDIRS=`pwd` modules_install
	@echo "Installing virtio_crypto.h in $(PREFIX)/usr/include/linux ..."
	@install -D virito_crypto.h $(PREFIX)/usr/include/linux/virtio_crypto.h

clean:
	make -C $(KERNEL_DIR) SUBDIRS=`pwd` clean
	rm -f $(hostprogs) *~

CPOPTS =
ifneq (${SHOW_TYPES},)
CPOPTS += --show-types
endif
ifneq (${IGNORE_TYPES},)
CPOPTS += --ignore ${IGNORE_TYPES}
endif

checkpatch:
	$(KERNEL_DIR)/scripts/checkpatch.pl ${CPOPTS} --file *.c *.h

OUTPUT = $(FILEBASE).tar.gz

dist: clean
	@echo Packing
	@rm -f *.tar.gz
	@git archive --format=tar.gz --prefix=$(FILEBASE)/ --output=$(OUTPUT) $(VERSIONTAG)
	@echo Signing $(OUTPUT)
	@gpg --output $(OUTPUT).sig -sb $(OUTPUT)
	@gpg --verify $(OUTPUT).sig $(OUTPUT)
