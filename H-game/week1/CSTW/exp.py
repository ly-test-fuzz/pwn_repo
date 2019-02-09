#encoding:utf-8
from pwn import *
from string import printable
context.log_level = "debug"
flag = "hgame{Ch1p_1s_Awakking!"
for i in range(0x18):
	# p = process("./CSTW")
	p = remote("118.24.3.214" , 10001)
	p.recvline()
	for i in range(5):
		p.sendline("")
		p.recvline()
	for j in  printable:
		temp = flag + j + "\x00"
		p.send(temp)
		result = p.recvline()
		if "觉醒了" in result:
			flag += j
			print(result)
			print(flag)
			p.close()
			break
		else:
			p.recvline()
	break
print(flag)
	