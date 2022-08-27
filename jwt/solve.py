from base64 import urlsafe_b64decode, urlsafe_b64encode
from fastecdsa.curve import secp256k1
from hashlib import sha256
from Crypto.Util.number import bytes_to_long as btl
import json

"""
Looking at the jwt implementation we can immediately notice the private key "k" in the _sign() function is constant. 
This in combination with us being able to create new accounts sets up a classical example of a broken ECDSA implementation. 
The details of the algebra can be found in the wikipedia page (https://en.wikipedia.org/wiki/Elliptic_Curve_Digital_Signature_Algorithm#Signature_generation_algorithm) and at https://github.com/Bumbodosan/tenable2021/tree/main/ECDSA-Implementation-Review
"""

def b64decode(msg: str) -> bytes:
    if len(msg) % 4 != 0:
        msg += "=" * (4 - len(msg) % 4)
    return urlsafe_b64decode(msg.encode())

def b64encode(msg: bytes) -> str:
    return urlsafe_b64encode(msg).decode().rstrip("=")

# create two distinct accounts and copy their cookies
cookie1 = "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjoiYWl2aWFnaG9zdCJ9.75J83TiCMONIDtDLvDQ8FKHa4wx7DNHkauX-Izu11S9Da-vuVWjKlrN3Y4BgGcTbR4StvBFcyXsl0ZL7fg13-A"
cookie2 = "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjoiY3JpbmdlIn0.75J83TiCMONIDtDLvDQ8FKHa4wx7DNHkauX-Izu11S-ax_jWCvKG5RXy8sTJqq-kSStP3LDxXa8pEmhPavVEAQ"

h1, d1, sig1 = map(b64decode, cookie1.split("."))
h2, d2, sig2 = map(b64decode, cookie2.split("."))

# "header" and "data" sections from cookie1 and cookie2
msg1 = "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjoiYWl2aWFnaG9zdCJ9"
msg2 = "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjoiY3JpbmdlIn0"

r1, s1 = int.from_bytes(sig1[ : 32], "little"), int.from_bytes(sig1[32 : ], "little")
r2, s2 = int.from_bytes(sig2[ : 32], "little"), int.from_bytes(sig2[32 : ], "little")

assert r1 == r2
assert s1 != s2

G = secp256k1.G
order = secp256k1.q

z1 = btl(sha256(msg1.encode()).digest())
z2 = btl(sha256(msg2.encode()).digest())

k = (((z1 - z2) % order) * pow(s1 - s2, -1, order)) % order
priv = ((((s1 * k) % order) - z1) * pow(r1, -1, order)) % order

def sign2(msg):
    z = sha256(msg.encode()).digest()
    k = priv
    z = btl(z)
    r = (k * G).x
    s = pow(k, -1, order) * (z + r * priv) % order
    return r, s

def sign(data):
    print("here")
    header = b64encode(
        json.dumps({"alg": "ES256", "typ": "JWT"}).replace(" ", "").encode()
    )
    data = b64encode(json.dumps(data).replace(" ", "").encode())
    r, s = sign2(header + "." + data)
    signature = r.to_bytes(32, "little") + s.to_bytes(32, "little")
    return header + "." + data + "." + b64encode(signature)

print(sign({"user": "admin"}))

# maple{3ll1pt!c_c2rv3s_f7w!!!}
