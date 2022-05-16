import hashlib

def hash256(s: str):
    return hashlib.sha256(hashlib.sha256(s.encode()).digest()).digest()