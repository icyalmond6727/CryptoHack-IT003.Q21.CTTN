import json
import math
from pwn import *

HOST = "socket.cryptohack.org"
PORT = 13423

ALPHABET = b"0123456789abcdef"

def solve():
    r = remote(HOST, PORT)
    r.recvline()

    r.sendline(json.dumps({"option": "encrypt"}).encode())
    res = json.loads(r.recvline().decode())
    
    ct_hex = res["ct"]
    ct_bytes = bytes.fromhex(ct_hex)
    
    blocks = [ct_bytes[i:i+16] for i in range(0, len(ct_bytes), 16)]
    
    flag_hex = bytearray()
    
    for block_idx in [1, 2]:
        C_prev = blocks[block_idx - 1]
        C_curr = blocks[block_idx]
        
        intermediate = bytearray(16)
        plaintext = bytearray(16)
        
        for pad_val in range(1, 17):
            idx = 16 - pad_val
            
            scores = {c: 0.0 for c in ALPHABET}
            
            while True:
                max_score = max(scores.values())
                sum_exp = sum(math.exp(s - max_score) for s in scores.values())
                probs = {c: math.exp(s - max_score) / sum_exp for c, s in scores.items()}
                
                winner = max(probs, key=probs.get)
                
                if probs[winner] > 0.999:
                    print(f"[*] Block {block_idx} - Byte {idx:02d} found: {chr(winner)} (Weight: {probs[winner]:.4f})")
                    plaintext[idx] = winner
                    intermediate[idx] = winner ^ pad_val ^ C_prev[idx]
                    break
                
                candidates = [c for c in ALPHABET if probs[c] > 0.001]
                
                for i in range(0, len(candidates), 8):
                    batch = candidates[i:i+8]
                    
                    for guess in batch:
                        C_prev_mod = bytearray(C_prev)
                        
                        for j in range(idx + 1, 16):
                            C_prev_mod[j] = intermediate[j] ^ pad_val
                            
                        C_prev_mod[idx] = guess ^ pad_val ^ C_prev[idx]
                        
                        payload = (C_prev_mod + C_curr).hex()
                        req = {"option": "unpad", "ct": payload}
                        r.sendline(json.dumps(req).encode())
                        
                    for guess in batch:
                        resp = json.loads(r.recvline().decode())
                        
                        if resp["result"] == False:
                            scores[guess] += math.log(0.6 / 0.4)
                        else:
                            scores[guess] += math.log(0.4 / 0.6)
                            
        flag_hex += plaintext
        print(f"[+] Block {block_idx}: {plaintext.decode()}")
        
    recovered_message = flag_hex.decode()
    print(f"\n[+] Recovered message: {recovered_message}")
    
    r.sendline(json.dumps({"option": "check", "message": recovered_message}).encode())
    final_response = json.loads(r.recvline().decode())
    
    print("\n[+] Flag:")
    print(json.dumps(final_response, indent=4))
    r.close()

if __name__ == "__main__":
    solve()