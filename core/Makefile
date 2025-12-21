# CTAE Core Module Makefile
# Builds the core topology discovery module

obj-m += ctae_core.o

# Kernel build directory
KDIR := /lib/modules/$(shell uname -r)/build

# Current directory
PWD := $(shell pwd)

# Compiler flags for debugging (optional, remove for production)
ccflags-y := -DDEBUG -g -Wall

all:
	@echo "Building CTAE Core Module..."
	$(MAKE) -C $(KDIR) M=$(PWD) modules

clean:
	@echo "Cleaning CTAE Core Module..."
	$(MAKE) -C $(KDIR) M=$(PWD) clean
	rm -f Module.symvers modules.order

install: all
	@echo "Installing CTAE Core Module..."
	sudo insmod ctae_core.ko

uninstall:
	@echo "Removing CTAE Core Module..."
	sudo rmmod ctae_core

reload: uninstall install

info:
	@echo "Module Information:"
	modinfo ctae_core.ko

test:
	@echo "Checking if module is loaded..."
	lsmod | grep ctae_core || echo "Module not loaded"
	@echo ""
	@echo "Recent kernel messages:"
	dmesg | tail -30 | grep CTAE

.PHONY: all clean install uninstall reload info test