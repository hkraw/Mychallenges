all:
	gcc -Wl,-z,now -fpie -fstack-protector-all -s butterfly.c -o butterfly
	strip butterfly
clean:
	rm butterfly

