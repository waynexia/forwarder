ifneq ($(KERNELRELEASE),)
    obj-m += confirm.o
else
    PWD := $(shell pwd)
    KVER := $(shell uname -r)
    KDIR := /lib/modules/$(KVER)/build
default:    
	$(MAKE) -C $(KDIR)  M=$(PWD) modules
all:
	make -C $(KDIR) M=$(PWD) modules 
clean:
	rm -rf *.o *.mod.c *.ko *.symvers *.order *.makers
endif
