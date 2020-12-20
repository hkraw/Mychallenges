#include <stdio.h>
#include <stdlib.h>
#include <malloc.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <stdint.h>
#include "SECCOMP.h"

struct sock_filter seccompfilter[]={
	BPF_STMT(BPF_LD | BPF_W | BPF_ABS, ArchField),
	BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, AUDIT_ARCH_X86_64, 1, 0),
	BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL),
	BPF_STMT(BPF_LD | BPF_W | BPF_ABS, SyscallNum),
	Allow(open),
	Allow(read),
	Allow(write),
	Allow(mprotect),
	Allow(clock_nanosleep),
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

int64_t cookie = 0xdeadbeefdeadbeefLL;
char* tcache_struct;
const char nline = '\n';
char *note[0x100];
uint32_t sizes[0x100];

void * mycalloc(size_t size) {
	void *tmp;
	memset(tcache_struct,0,0x280); //Tcache is for weaks. ^^
	tmp = malloc(size);
	if (tmp) {
		return tmp;
	}
	_exit(0x31337);
}

void myprintf(char *buffer) {
	size_t size;
	size = strlen(buffer);
	write(1, buffer, size);
	return ;
}

void myputs(const char *buffer) {
	size_t size;
	size = strlen(buffer);
	write(1, buffer, size);
	write(1, &nline, 1);
	return ;
}

uint32_t return_number() {
	char buff[0x10];
	read(STDIN_FILENO, buff, 0x4);
	buff[0x4] = '\0';
	return atoi(buff);
}

void myread(char *buffer, size_t len) {
	size_t res;
	res = read(STDIN_FILENO, buffer, len);
	if (res <= 0)
		_exit(1);
	buffer[res - 1] = '\0';
}

void apply_seccomp() {
	if(prctl(PR_SET_NO_NEW_PRIVS,1,0,0,0)) {
		myprintf("Seccomp Error");
		_exit(1);
	}
	if(prctl(PR_SET_SECCOMP,SECCOMP_MODE_FILTER,&filterprog)==-1) {
		myprintf("Seccomp Error");
		_exit(1);
	}
	return ;
}

void add() {
	uint32_t idx;
	size_t size;
	for(idx=0;idx<19;idx++) {
		if(!note[idx]) {
			break;
		}
	}
	if(idx>=19)
		_exit(1);
	myprintf("Size: ");
	size = (uint32_t) return_number();
	if( ( size > 0x100 && size <= 0x2000 ) ) {
		note[idx] = (char *) mycalloc(size);
		sizes[idx] = size;
		myprintf("Data: ");
		myread(note[idx],size);
	}
}

void delete() {
	uint32_t idx;
	myprintf("Index: ");
	idx = (uint32_t) return_number();
	if(idx >= 0x0 && idx < 19 && note[idx]) {
		free(note[idx]);
		note[idx] = NULL;
		sizes[idx] = 0;
	}
}

void view() {
	uint32_t idx;
	myprintf("Index: ");
	idx = (uint32_t) return_number();
	if(idx >= 0x0 && idx < 19 && note[idx])
		myputs(note[idx]);
}

void edit() {
	if(cookie != 0xdeadbeefdeadbeefLL)
		_exit(1) ;
	uint32_t idx;
	myprintf("Index: ");
	idx = (uint32_t) return_number();
	if(idx >= 0x0 && idx < 19 && note[idx]) {
		size_t read_len = read(STDIN_FILENO,note[idx],sizes[idx]);
		if (read_len <= 0)
			_exit(1);
		note[idx][read_len] = '\0';
		cookie = 0;
	}
}

void init() {
	alarm(1000);
	setvbuf(stdout,0,2,0);
	tcache_struct = malloc(0x18) - 0x290;
	apply_seccomp();
}

int main() {
	init();
	uint32_t choice;
	while(1) {
		sleep(2);
		myputs("|> ");
		myprintf("| ");
		choice = return_number();
		switch(choice) {
			case 1:
				add();
				break;
			case 2:
				delete();
				break;
			case 3:
				view();
				break;
			case 4:
				edit();
				break;
			case 5:
				_exit(0x31337);
			default:
				myputs("Wrong choice (-^^-)");
		}
	}
}
