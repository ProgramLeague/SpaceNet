obj-m := forward_module.o
#obj-m := filter.o
forward_module-objs := hash.o chunk_table.o ack_sent.o wait_ack.o token.o netlink.o util.o send.o \
req_handler.o resp_handler.o hsyn_handler.o ack_handler.o needmore_handler.o filter.o register.o
KERNELBUILD :=/lib/modules/$(shell uname -r)/build
KBUILD_CFLAGS += -DDEBUG

default:
	make -C $(KERNELBUILD) M=$(shell pwd) modules 
clean:
	rm -rf *.o *.ko *.mod.c .*.cmd *.markers *.order *.symvers .tmp_version
