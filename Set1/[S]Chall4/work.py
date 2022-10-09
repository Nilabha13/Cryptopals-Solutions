from base64 import b16decode, b16encode
from cryptopals_utils import score_text, byte_xor

filename = "4.txt"
input = [line.strip().encode() for line in open(filename, 'r').readlines()]


input_bytes = [b16decode(line, casefold=True) for line in input]
min_score = float('inf')
dec = b''
for line in input_bytes:
	for i in range(256):
		decrypted = byte_xor(chr(i).encode(), line)
		score = score_text(decrypted)
		if score < min_score:
			min_score = score
			dec = decrypted
        
try:
	print(dec.decode())
except:
	print("[-] ERROR: Decryption not expressible in ASCII; Incorrect decryption!")
