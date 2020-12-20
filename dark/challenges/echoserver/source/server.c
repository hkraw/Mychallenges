#include<stdio.h>
#include<stdlib.h>
#include<unistd.h>

void fuck();
int main()
{
	FILE* dev_null;
	setvbuf(stdin,0,2,0);
	setvbuf(stdout,0,2,0);
	setvbuf(stderr,0,2,0);
	alarm(60);
	dev_null = fopen("/dev/null","wb");
	fuck(dev_null);
	fclose(dev_null);
	printf("Bye");
	return 0;
}

void fuck(FILE* f)
{
	char *something_cool;
	char *buff;
	char *aaa;
	char *bbb;
	char *ccc;
	aaa = &bbb;
	bbb = &ccc;
	something_cool = &buff;
	buff = (char *)malloc(0x200);
	printf("> ");
	fflush(stdout);
	read(0,buff,0x100);
	printf("> ");
	fprintf(f, buff);
	return ;
}
