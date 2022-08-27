from pwn import remote
from utils import spiralRight

"""
We notice each character in a plaintext block only affects one character in the ciphertext. 
Even more important the position of the affected character position is only dependant on the position of the input character. 
That is for each index i in the ciphertext, that position is only affected by the plaintext character at position j, independent of key and value of the plaintext character.
This means we can build a lookup table based on the value of a character in the output and its position. 
We can precompute which indices are related in the plaintext and ciphertext and then build the lookup table based on cipher values by querying the servince. 
We actually only need to make one request since we can just send one long plaintext and use the fact that they are technically using ECB-mode, the blocks of the cipher are unrelated to eachother.
With the lookup table we can easily decrypt the flag. 

FLAG: maple{0nt0_th3_r34l_sp!r4l_0be088}
"""

index_lookup = {}
m = sum(spiralRight([list(range(i, i + 4)) for i in range(0, 16, 4)]), [])
for i in range(16):
    index_lookup[m.index(i)] = i


def encrypt(r, pt):
    r.recv()
    r.sendline(b"2")
    r.sendline(pt.hex().encode())
    return bytes.fromhex(r.recvline().decode())


r = remote(*"spiral-baby.ctf.maplebacon.org 1337".split())


long_ct = encrypt(r, b"".join(bytes([i] * 16) for i in range(255)))
lookup = {}
for i in range(255):
    for j in range(16):
        lookup[(j, long_ct[i * 16 + j])] = (index_lookup[j], i)

assert len(lookup) == 255 * 16

r.recv()
r.sendline(b"1")

enc_flag = bytes.fromhex(r.recvline().decode())

flag_blocks = [enc_flag[i : i + 16] for i in range(0, len(enc_flag), 16)]
flag = b""
for block in flag_blocks:
    dec = [0] * 16
    for i, fc in enumerate(block):
        j, pc = lookup[(i, fc)]
        dec[j] = pc
    flag += bytes(dec)

def unpad_pkcs7(data: bytes) -> bytes:
    if len(data) % 16 != 0 or not (1 <= data[-1] <= 16) or not all(i == data[-1] for i in data[-data[-1] : ]):
        raise ValueError("Data is not padded with valid PKCS#7!")
    return data[ : -data[-1]]

FLAG = unpad_pkcs7(flag).decode()

print(f"FLAG: {FLAG}")
