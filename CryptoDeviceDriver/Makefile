obj-m+=cryptomodule.o

all:
	make -C /lib/modules/$(shell uname -r)/build/ M=$(PWD) modules
	sudo insmod cryptomodule.ko
	$(CC) cryptoModuleTest.c -o test
	
clean:
	sudo rmmod cryptomodule
	make -C /lib/modules/$(shell uname -r)/build/ M=$(PWD) clean
	rm test
