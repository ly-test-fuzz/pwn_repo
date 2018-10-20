from pwn import  *
fpath = "./random"
p = process(fpath)

target = 0xDEADBEEF

low = 12
high =  target ^ low
high , low = low , high
temp = high * (16 ** 8) + low
p.sendline(str(temp))
print p.recv()

