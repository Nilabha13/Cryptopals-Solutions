from base64 import b16decode
from cryptopals_utils import xor

def byte_xor(xor_byte, byte_string):
	return xor(byte_string, xor_byte*len(byte_string))


def score_text(text):
	letters = "abcdefghijklmnopqrstuvwxyz"
	freq = {"a": 8.167, "b": 1.492, "c": 2.782, "d": 4.253, "e": 12.702, "f": 2.228, "g": 2.015, "h": 6.094, "i": 6.966, "j": 0.153, "k": 0.772, "l": 4.025, "m": 2.406, "n": 6.749, "o": 7.507,  "p": 1.929, "q": 0.095, "r": 5.987, "s": 6.327, "t": 9.056, "u": 2.758, "v": 0.978, "w": 2.360, "x": 0.150, "y": 1.974, "z": 0.074}

	counts = {}
	for char in letters:
		counts[char] = 0
	for byte in text:
		if ord('a') <= byte and byte <= ord('z'):
			counts[chr(byte)] += 1

	text_freq = {}
	for char in letters:
		text_freq[char] = counts[char] * 100/len(text)

	score = 0
	for char in letters:
		score += abs(freq[char] - text_freq[char])
	score /= len(text)

	return score


input = b'1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736'

input_bytes = b16decode(input, casefold=True)
min_score = float('inf')
dec = b''
for i in range(256):
	decrypted = byte_xor(chr(i).encode(), input_bytes)
	score = score_text(decrypted)
	if score < min_score:
		score = min_score
		dec = decrypted
        
try:
	print(dec.decode())
except:
	print("[-] ERROR: Decryption not expressible in ASCII; Incorrect decryption!")
