from base64 import b64decode
from cryptopals_utils import xor
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES
from pwn import p64

ct = b"L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ=="
ct_bytes = b64decode(ct)

key = b"YELLOW SUBMARINE"
nonce = b"\x00"*8

def aes_ctr(input_stream, key, nonce=None, initial_value=0):
    if nonce == None:
        nonce = get_random_bytes(8)

    cipher = AES.new(key, AES.MODE_ECB)
    num_blocks = len(input_stream)//16
    xor_stream = b""
    for i in range(num_blocks):
        xor_stream += cipher.encrypt(nonce + p64(initial_value+i))

    return xor(input_stream, xor_stream)


try:
    print(f"[+] PLAINTEXT: {aes_ctr(ct_bytes, key, nonce=nonce).decode()}")
except:
    print("[-] Decryption not expressible in ascii! Invalid decryption!")

