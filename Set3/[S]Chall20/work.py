from base64 import b64decode
from cryptopals_utils import score_text, repeat_xor, byte_xor

filename = "20.txt"
input = [line.strip() for line in open(filename, 'r').readlines()]
input_bytes = [b64decode(line) for line in input]

min_length = float('inf')
for line in input_bytes:
    if len(line) < min_length:
        min_length = len(line)

trunc_cts = [line[:min_length] for line in input_bytes]

def crack_byte_xor(ct):
    min_score = float('inf')
    key = None
    for i in range(256):
        score = score_text(byte_xor(chr(i).encode(), ct))
        if score < min_score:
            min_score = score
            key = chr(i).encode()
    return key

master_ct = b''.join(trunc_cts)
keysize = min_length
chunks = [master_ct[i::keysize] for i in range(keysize)]
key = b''.join(crack_byte_xor(chunk) for chunk in chunks)

master_pt = repeat_xor(key, master_ct)
trunc_pts = [master_pt[i:i+min_length] for i in range(0, len(master_pt), min_length)]

try:
    for line in trunc_pts:
        print(line.decode())
except:
    print("[-] Decryption not expressible in ascii! Invalid decryption!")
