import hmac, hashlib
from hashlib import sha256

BLOCK_SIZE = 64
HASH_LEN = 32
OPAD = b"\x5c" * BLOCK_SIZE
IPAD = b"\x36" * BLOCK_SIZE

# --- your current implementation (key as str) ---
def k_to_ko(k: str) -> bytes:
    kb = k.encode()
    if len(kb) > HASH_LEN:
        ko = hashlib.sha256(kb).digest()
    else:
        ko = kb.ljust(HASH_LEN, b"\x00")
    return ko

def get_inner_hash(ko, msg):
    kb = ko.ljust(BLOCK_SIZE, b"\x00")
    k_ipad = bytes(a ^ b for a, b in zip(kb, IPAD))
    return hashlib.sha256(k_ipad + msg).digest()

def get_outer_hash(ko, inner):
    kb = ko.ljust(BLOCK_SIZE, b"\x00")
    k_opad = bytes(a ^ b for a, b in zip(kb, OPAD))
    return hashlib.sha256(k_opad + inner).digest()

def yours(key_str, msg):
    ko = k_to_ko(key_str)
    return get_outer_hash(ko, get_inner_hash(ko, msg))

def mine(key, isis_apad):
    if len(key) > HASH_LEN:
        key = sha256(key).digest()
    return hmac.new(key, isis_apad, sha256).digest()

msg = b"some fake ISIS PDU bytes || APAD here"
tests = ["toto", "", "a", "password123", "x"*31, "x"*32, "x"*33, "x"*63, "x"*64, "x"*100]
for k in tests:
    y = yours(k, msg)
    m = mine(k.encode(), msg)
    print(f"len={len(k):>3}  match={y==m}")
