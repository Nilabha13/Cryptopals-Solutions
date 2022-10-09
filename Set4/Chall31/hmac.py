from hashlib import sha1
from cryptopals_utils import xor

def hmac_sha1(key, msg):
    def compute_block_sized_key(key):
        if len(key) > 64:
            key = hash(key)
        elif len(key) < 64:
            key = key + chr(0).encode()*(64-len(key))
        return key

    def hash(data):
        h = sha1()
        h.update(data)
        return h.digest()

    block_sized_key = compute_block_sized_key(key)

    o_key_pad = xor(block_sized_key, chr(0x5c).encode()*64)
    i_key_pad = xor(block_sized_key, chr(0x36).encode()*64)

    return hash(o_key_pad + hash(i_key_pad + msg)).hex()

if __name__ == "__main__":
    assert hmac_sha1(b"key", b"The quick brown fox jumps over the lazy dog") == "de7c9b85b8b78aa6bc8a7a36f70a90701c9db4d9"
    print("[+] Assertion passed!")
