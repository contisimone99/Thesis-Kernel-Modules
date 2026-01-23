EXTRA_CFLAGS  := -g

obj-m:=fx-bootstrap.o
all:
	make -C ~/Thesis-Kernel-Modules/linux M=$(shell pwd) modules
clean:
	make -C ~/Thesis-Kernel-Modules/linux M=$(shell pwd) clean
