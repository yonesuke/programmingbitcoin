import hashlib

BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

def hash160(s: str) -> bytes:
    """
    apply ripemd160 after sha256
    """
    return hashlib.new("ripemd160", hashlib.sha256(s).digest()).digest()

def hash256(s: str) -> bytes:
    """
    apply hash256 two times
    """
    return hashlib.sha256(hashlib.sha256(s).digest()).digest()

def encode_base58(s: str) -> str:
    count = 0
    for c in s:
        if c == 0:
            count += 1
        else:
            break
    num = int.from_bytes(s, "big")
    prefix = BASE58_ALPHABET[0] * count
    result = ""
    while num > 0:
        num, mod = divmod(num, 58)
        result = BASE58_ALPHABET[mod] + result
    return prefix + result

def encode_base58_checksum(b: bytes) -> str:
    return encode_base58(b + hash256(b)[:4])

def little_endian_to_int(b: bytes) -> int:
    return int.from_bytes(b, "little")

def int_to_little_endian(n: int, length: int) -> bytes:
    return n.to_bytes(length, "little")