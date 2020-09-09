obj-m += cryptomodule.o

all:
	#compilar módulo
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules
	sudo insmod cryptomodule.ko

	#compilar programa em espaço de usuario
	$(CC) cryptoModuleTest.c -o test
	./test

clean:
	#remover módulo
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean

	#remover programa em espaço de usuário
	rm test
