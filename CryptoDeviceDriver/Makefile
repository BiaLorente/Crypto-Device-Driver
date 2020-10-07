obj-m+=cryptomodule.o

all:
	make -C /lib/modules/$(shell uname -r)/build/ M=$(PWD) modules
	sudo insmod cryptomodule.ko key="0123456789ABCDEF" iv="0123456789ABCDEF"
	$(CC) cryptoModuleTest.c -o test
	sudo ./test
	
clean:
	sudo rmmod cryptomodule
	sudo rm test
	make -C /lib/modules/$(shell uname -r)/build/ M=$(PWD) clean
