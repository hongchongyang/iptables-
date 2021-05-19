obj-m:=grab.o
grab-objs:=main.o ip2str.o uc2str.o uc2int.o
grab-objs+=eth_if.o

all:
	make -C /lib/modules/`uname -r`/build M=`pwd` modules
clean:
	make -C /lib/modules/`uname -r`/build M=`pwd` clean
start:
	/sbin/insmod grab.ko
stop:
	/sbin/rmmod grab.ko
