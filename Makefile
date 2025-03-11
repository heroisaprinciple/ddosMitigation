# an obj file
obj-m += ddosMitigation.o

# linux kernel headers are here
KDIR = /lib/modules/$(shell uname -r)/build

# a target, tells the kernel to build the module
all:
	make -C $(KDIR) M=$(shell pwd) modules

# removes generated files with sudo clean 
clean:
	make -C $(KDIR) M=$(shell pwd) clean
