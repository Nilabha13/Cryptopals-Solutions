from base64 import b64decode
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from cryptopals_utils import aes_ctr

#==============================

filename = "25.txt"
input_bytes = b64decode(open(filename, 'r').read().replace('\n', ''))
cipher = AES.new(b'YELLOW SUBMARINE', AES.MODE_ECB)
pt = cipher.decrypt(input_bytes)
key = get_random_bytes(16)
ct_public = aes_ctr(pt, key, b'\x00'*8)

def edit(ciphertext, offset, newtext, key=key):
    plaintext = aes_ctr(ciphertext, key, b'\x00'*8)
    plaintext = plaintext[:offset] + newtext + plaintext[offset:]
    return aes_ctr(plaintext, key, b'\x00'*8)

#==============================

new_ct = edit(ct_public, 0, ct_public)
pt_found = new_ct[:len(ct_public)]

try:
    print(pt_found.decode())
except:
    print("[-] Decryption not expressible in ascii! Invalid decryption!")
