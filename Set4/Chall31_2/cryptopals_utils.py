from itertools import cycle
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from pwn import p64

def xor(bs1, bs2):
	return bytes(c1^c2 for (c1, c2) in zip(bs1, bs2))


def byte_xor(xor_byte, byte_string):
	return xor(byte_string, xor_byte*len(byte_string))


def repeat_xor(key, byte_string):
	return bytes(c1^c2 for (c1, c2) in zip(byte_string, cycle(key)))


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
	
	
def detect_aes_ecb(byte_string, BLOCK_SIZE=16):
	chunks = [byte_string[i:i+BLOCK_SIZE] for i in range(0, len(byte_string), BLOCK_SIZE)]
	uniq_chunks = set(chunks)
	return True if len(chunks) != len(uniq_chunks) else False
	
	
def pkcs7_pad(byte_string, BLOCK_SIZE=16):
    pad_num = BLOCK_SIZE - (len(byte_string)%BLOCK_SIZE)
    return byte_string + chr(pad_num).encode()*pad_num


def pkcs7_unpad(byte_string, BLOCK_SIZE=16):
	if len(byte_string) < BLOCK_SIZE:
		raise Exception("Incorrect Padding!")
	padbyte = byte_string[-1]
	if padbyte > BLOCK_SIZE:
		raise Exception("Incorrect Padding!")
	if byte_string[-padbyte:] != chr(padbyte).encode()*padbyte:
		raise Exception("Incorrect Padding!")
	return byte_string[:-padbyte]
	

def aes_ctr(input_stream, key, nonce=None, initial_value=0):
    if nonce == None:
        nonce = get_random_bytes(8)

    cipher = AES.new(key, AES.MODE_ECB)
    num_blocks = len(input_stream)//16
    xor_stream = b""
    for i in range(num_blocks):
        xor_stream += cipher.encrypt(nonce + p64(initial_value+i))

    return xor(input_stream, xor_stream)


class MT19937:
    def __init__(self, seed=5489):
        self._w, self._n, self._m, self._r = 32, 624, 397, 31
        self._a = 0x9908b0df
        self._u, self._d = 11, 0xffffffff
        self._s, self._b = 7, 0x9d2c5680
        self._t, self._c = 15, 0xefc60000
        self._l = 18
        self._f = 1812433253

        self._MT = [0]*self._n
        self._index = self._n+1
        self._lower_mask = (1 << self._r) - 1
        self._upper_mask = ((1 << self._w) - 1) - self._lower_mask

        self._seed_mt(seed)

    def _seed_mt(self, seed):
        self._index = self._n
        self._MT[0] = seed & ((1 << self._w) - 1)
        for i in range(1, self._n):
            self._MT[i] = (self._f * (self._MT[i-1] ^ (self._MT[i-1] >> (self._w - 2))) + i) & ((1 << self._w) - 1)

    def _twist(self):
        for i in range(self._n):
            x = (self._MT[i] & self._upper_mask) + (self._MT[(i+1) % self._n] & self._lower_mask)
            xA = x >> 1
            if x%2 != 0:
                xA = xA ^ self._a
            self._MT[i] = self._MT[(i+self._m)%self._n] ^ xA
        self._index = 0

    def random(self):
        if self._index == self._n:
            self._twist()

        y = self._MT[self._index]
        y = y ^ ((y >> self._u) & self._d)
        y = y ^ ((y << self._s) & self._b)
        y = y ^ ((y << self._t) & self._c)
        y = y ^ (y >> self._l)

        self._index = self._index + 1
        return y & ((1 << self._w) - 1)
