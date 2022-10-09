from base64 import b64decode
from cryptopals_utils import xor
from Crypto.Cipher import AES

filename = "10.txt"
input = open(filename, 'r').read().replace('\n', '')
key = b"YELLOW SUBMARINE"
iv = b'0'*16

input_bytes = b64decode(input)

def aes_cbc_decrypt(key, iv, ciphertext):
    ct_blocks = [ciphertext[i:i+16] for i in range(0, len(ciphertext), 16)]
    xor_block = iv
    pt_blocks = []
    cipher = AES.new(key, AES.MODE_ECB)
    for ct_block in ct_blocks:
        inter_block = cipher.decrypt(ct_block)
        pt_block = xor(inter_block, xor_block)
        pt_blocks.append(pt_block)
        xor_block = ct_block
    return b''.join(pt_blocks)


pt = aes_cbc_decrypt(key, iv, input_bytes)
try:
    print(pt.decode())
except:
    print("[-] ERROR: Decryption is not expressible in ascii! Invalid decryption!")
