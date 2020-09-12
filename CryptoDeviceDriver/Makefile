obj-m+=cryptomodule.o

all:
	make -C /lib/modules/$(shell uname -r)/build/ M=$(PWD) modules
	sudo insmod cryptomodule.ko
	$(CC) cryptoModuleTest.c -o test
	sudo ./test
	
clean:
	sudo rmmod cryptomodule
	rm test
	make -C /lib/modules/$(shell uname -r)/build/ M=$(PWD) clean
