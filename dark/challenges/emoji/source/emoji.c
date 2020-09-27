#include<stdio.h>
#include<string.h>
#include<stdlib.h>
#include<unistd.h>
#include<fcntl.h>
#include"SECCOMP.h"

struct sock_filter seccompfilter[]={
  BPF_STMT(BPF_LD | BPF_W | BPF_ABS, ArchField),
  BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, AUDIT_ARCH_X86_64, 1, 0),
  BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL),
  BPF_STMT(BPF_LD | BPF_W | BPF_ABS, SyscallNum),
  Allow(read),
  Allow(write),
  Allow(open),
  Allow(mprotect),
  Allow(rt_sigreturn),
  Allow(brk),
  Allow(exit),
  Allow(exit_group),
  BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL),
};

struct sock_fprog filterprog={
  .len=sizeof(seccompfilter)/sizeof(struct sock_filter),
  .filter=seccompfilter
};

int HK = 0x1337;
char name[0x20];
char *note[0x5];
char nline = '\n';

void myprintf(char *buffer)
{
	int lol;
	lol = strlen(buffer);
	write(1,buffer,lol);
}

void myputs(char *buffer)
{
	int lol;
	lol = strlen(buffer);
	write(1,buffer,lol);
	write(1,&nline,1);
}

void apply_seccomp(){
  if(prctl(PR_SET_NO_NEW_PRIVS,1,0,0,0)){
    myprintf("Seccomp Error");
    _exit(1);
  }
  if(prctl(PR_SET_SECCOMP,SECCOMP_MODE_FILTER,&filterprog)==-1){
    myprintf("Seccomp Error");
    _exit(1);
  }
  return;
}

void readwrapper(char *buff, unsigned int size)
{
	int nbytes;
	nbytes = read(STDIN_FILENO,buff,size);
	if(buff[nbytes-1] == '\n') 
		buff[nbytes-1] = '\x00';
	return ;
}
long int num()
{
	char buff[0x10];
	read(STDIN_FILENO,buff,0x8);
	buff[0x8] = '\x00';
	return atoi(buff);
}

void whatthis(){
	unsigned int index;
	unsigned int size;
	if(!HK) return;
	myprintf("Enter the index: ");
	index = num();
	if(index < 0 || index > 0x4) return;
	if(note[index]) return;
	myprintf("Size: ");
	size = num();
	if(size>0xd0 || size <= 0x508){
		note[index] = (char *)calloc(1,size);
		if(!note[index]) {
			_exit(-1);
		}
		myprintf("Here you go: ");
		if(read(STDIN_FILENO,note[index],size)<=0) {
			_exit(-1);
		}
		note[index][size] = '\x00';
	}
	HK = 0; 
	myputs(":)");
}
void delete()
{
	unsigned int index;
	unsigned int size;
	myprintf("Enter index: ");
	index = num();
	if(index < 0 || index > 0x4 || !note[index]) return;
	free(note[index]);
	note[index] = NULL;
}
void view()
{
	unsigned int index;
	unsigned int size;
	myprintf("Enter index: ");
	index = num();
	if(index < 0 || index > 0x4 || !note[index]) return;
	myputs(note[index]);
	return ;
}
void add()
{
	unsigned int index;
	unsigned int size;
	myprintf("Enter index: ");
	index = num();
	if(index < 0 || index > 0x4 || note[index]) return;
	myprintf("Enter size: ");
	size = num();
	if(size>0xd0 || size<=0x508)  {
		myprintf("Data: ");
		note[index] = (char *)calloc(1,size);
		if(!note[index]) {
			_exit(-1);
		}
		readwrapper(note[index],size);
	}
	return ;
}
void editname()
{
	myprintf("Enter name:");
	readwrapper(name,0x20);
	myputs(name);
}
void printmenu()
{
	myprintf("1). 🤩\n");
	myprintf("2). 😆\n");
	myprintf("3). 😁\n");
	myprintf("4). 😄\n");
	myprintf("5). 😀\n");
	myprintf("6). 🤫\n");
	myprintf("🤔: ");
}
void init()
{
	setvbuf(stdin,0,2,0);
	setvbuf(stdout,0,2,0);
	setvbuf(stderr,0,2,0);
	apply_seccomp();
}
int main()
{
	init();
	int choice;
	while(1){
		printmenu();
		choice = num();
		switch(choice) {
			case 1: add(); break;
			case 2: delete(); break;
			case 3: view(); break;
			case 5: editname(); break;
			case 6: whatthis(); break;
			case 4: _exit(0x1337);
			default: myprintf("Wrong"); break;
		}
	}
}
