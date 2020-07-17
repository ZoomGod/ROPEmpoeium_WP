binsh = "/bin/sh\x00"
badchar = [98, 105, 99, 47, 32, 102, 110, 115]
xornum = 1
while 1:
    for x in binsh:
        tem = ord(x) ^ xornum
        if tem in badchar:
            xornum += 1
            break
        if x == "\x00":
            print xornum
            xornum += 1
    if xornum == 10:
        break
