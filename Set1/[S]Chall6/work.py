from cryptopals_utils import xor, byte_xor, repeat_xor, score_text
from base64 import b64decode
from itertools import combinations
from math import comb

filename = "6.txt"
input = open(filename, 'r').read().replace('\n', '').encode()
input_bytes = b64decode(input)


MIN_KEYSIZE = 2
MAX_KEYSIZE = 40
NUM_CHUNKS_HAMMING = 4
KS_TOLERANCE = 1

def hamming_distance(bs1, bs2):
	return bin(int(xor(bs1, bs2).hex(), 16)).count('1')

def crack_byte_xor(ct):
	min_score = float('inf')
	key = None
	for i in range(256):
		score = score_text(byte_xor(chr(i).encode(), ct))
		if score < min_score:
			min_score = score
			key = chr(i).encode()
	return key

assert hamming_distance(b"this is a test", b"wokka wokka!!!") == 37

nhd_ks_pairs = []
for keysize in range(MIN_KEYSIZE, MAX_KEYSIZE+1):
	chunks = []
	for i in range(NUM_CHUNKS_HAMMING):
		chunks.append(input_bytes[i*keysize : (i+1)*keysize])
	hamming_dist_sum = 0
	for (chunk1, chunk2) in combinations(chunks, 2):
		hamming_dist_sum += hamming_distance(chunk1, chunk2)
	avg_hamming_dist = hamming_dist_sum / comb(NUM_CHUNKS_HAMMING, 2)
	nhd_ks_pairs.append((avg_hamming_dist/keysize, keysize))
nhd_ks_pairs.sort()

for (nhd, keysize) in nhd_ks_pairs[:KS_TOLERANCE]:
	chunks = [input_bytes[i::keysize] for i in range(keysize)]
	key = b''.join(crack_byte_xor(chunk) for chunk in chunks)
	print("KEY: ", key)
	print("DECRYPTION:")
	try:
		print(repeat_xor(key, input_bytes).decode())
	except:
		print("[-] ERROR: Decryption not expressible in ASCII; Incorrect decryption!")
