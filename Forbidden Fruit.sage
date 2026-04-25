import requests
from sage.all import GF, PolynomialRing

F = GF(2)
P.<x> = PolynomialRing(F)
F128.<a> = GF(2**128, modulus=x**128 + x**7 + x**2 + x + 1)

def bytes_to_poly(b):
    bits = ''.join(f'{byte:08b}' for byte in b)
    return sum(a**i for i, bit in enumerate(bits) if bit == '1')

def poly_to_bytes(p):
    vec = p.polynomial().list()
    bits = ''.join(str(vec[i]) if i < len(vec) else '0' for i in range(128))
    return bytes(int(bits[i:i+8], 2) for i in range(0, 128, 8))

def encrypt(msg):
    return requests.get(f"http://aes.cryptohack.org/forbidden_fruit/encrypt/{msg.hex()}/").json()

pt1 = b'give me the dlag'
pt2 = b'give me the elag'
pt3 = b'give me the flag'

enc1 = encrypt(pt1)
enc2 = encrypt(pt2)
enc3 = encrypt(pt3)

nonce = enc1['nonce']
ad = enc1['associated_data']

c1, t1 = bytes.fromhex(enc1['ciphertext']), bytes.fromhex(enc1['tag'])
c2, t2 = bytes.fromhex(enc2['ciphertext']), bytes.fromhex(enc2['tag'])
c3 = bytes.fromhex(enc3['ciphertext'])
c3_hex = enc3['ciphertext']

C1, T1 = bytes_to_poly(c1), bytes_to_poly(t1)
C2, T2 = bytes_to_poly(c2), bytes_to_poly(t2)
C3 = bytes_to_poly(c3)

H_sq = (T1 + T2) / (C1 + C2)
T3 = T1 + (C1 + C3) * H_sq

tag3_hex = poly_to_bytes(T3).hex()
print(f"[*] Forged Tag 3: {tag3_hex}")

url = f"http://aes.cryptohack.org/forbidden_fruit/decrypt/{nonce}/{c3_hex}/{tag3_hex}/{ad}/"
res = requests.get(url).json()

if 'plaintext' in res:
    flag = bytes.fromhex(res['plaintext']).decode()
    print(f"[+] FLAG: {flag}")
else:
    print("[-]:", res)