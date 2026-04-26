import json
from pwn import *

HOST = "socket.cryptohack.org"
PORT = 13423

ALPHABET = b"0123456789abcdef"
THRESH = 0.999
EXPLORE = 2
BATCH = 8

def update_probs(probs, guess, is_false):
    a, b = (0.6, 0.4) if is_false else (0.4, 0.6)
    old_p = probs[guess]
    
    den = old_p * a + (1 - old_p) * b
    new_p = old_p * a / den
    
    scale = (1 - new_p) / (1 - old_p)
    for c in ALPHABET:
        if c == guess:
            probs[c] = new_p
        else:
            probs[c] *= scale

def solve():
    r = remote(HOST, PORT)
    
    try:
        r.recvline(timeout=0.5)
        r.recvline(timeout=0.5)
    except EOFError:
        pass

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
            
            probs = {c: 1.0 / 16.0 for c in ALPHABET}
            
            def forge_payload(guess):
                C_prev_mod = bytearray(C_prev)
                for j in range(idx + 1, 16):
                    C_prev_mod[j] = intermediate[j] ^ pad_val
                C_prev_mod[idx] = guess ^ pad_val ^ C_prev[idx]
                return (C_prev_mod + C_curr).hex()

            jobs = []
            for guess in ALPHABET:
                jobs.extend([guess] * EXPLORE)
                
            for i in range(0, len(jobs), BATCH):
                chunk = jobs[i:i+BATCH]
                
                for guess in chunk:
                    payload = forge_payload(guess)
                    r.sendline(json.dumps({"option": "unpad", "ct": payload}).encode())
                    
                for guess in chunk:
                    resp = json.loads(r.recvline().decode())
                    update_probs(probs, guess, not resp["result"])
            
            while True:
                winner = max(probs, key=probs.get)
                
                if probs[winner] >= THRESH:
                    print(f"[*] Block {block_idx} - Byte {idx:02d} found: {chr(winner)} (Chance: {probs[winner]:.4f})")
                    plaintext[idx] = winner
                    intermediate[idx] = winner ^ C_prev[idx]
                    break
                    
                chunk = [winner] * min(BATCH, 12000)
                for guess in chunk:
                    payload = forge_payload(guess)
                    r.sendline(json.dumps({"option": "unpad", "ct": payload}).encode())
                    
                for guess in chunk:
                    resp = json.loads(r.recvline().decode())
                    update_probs(probs, guess, not resp["result"])
                    
        flag_hex += plaintext
        print(f"[+] Block {block_idx} decoded: {plaintext.decode()}")
        
    recovered_message = flag_hex.decode()
    print(f"\n[+] Recovered message: {recovered_message}")
    
    r.sendline(json.dumps({"option": "check", "message": recovered_message}).encode())
    final_response = json.loads(r.recvline().decode())
    
    print("\n[+] Flag:")
    print(json.dumps(final_response, indent=4))
    r.close()

if __name__ == "__main__":
    solve()
