#include<stdio.h>
#include<stdlib.h>
#include<unistd.h>

void fuck();
int main()
{
	setvbuf(stdin,0,2,0);
	setvbuf(stdout,0,2,0);
	setvbuf(stderr,0,2,0);
	alarm(60);
	fuck();
	printf("Bye");
	return 0;
}

void fuck()
{
	char *buff;
	char *aaa;
	char *bbb;
	char *ccc;
	aaa = &bbb;
	bbb = &ccc;
	buff = (char *)malloc(0x200);
	printf("> ");
	fflush(stdout);
	read(0,buff,0x40);
	printf("> ");
	printf(buff);
	return ;
}
