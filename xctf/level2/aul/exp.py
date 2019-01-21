from pwn import *

p = remote("111.198.29.45" , 30819)
p.recvuntil("| 3 2 1 4 4 a 2 4 |\n")
p.sendline("help")
content = p.recvuntil("\x00Didn't understand." , drop = True)
f = open("server.luac" , "wb")
f.write("\x1b" + content + "\x00")
f.close()
# p.interactive()
