from base64 import b16encode, b16decode

def xor(bs1, bs2):
	return bytes(c1^c2 for (c1, c2) in zip(bs1, bs2))

input1 = b'1c0111001f010100061a024b53535009181c'
input2 = b'686974207468652062756c6c277320657965'
expected_output = b'746865206b696420646f6e277420706c6179'

input1_bytes = b16decode(input1, casefold=True)
input2_bytes = b16decode(input2, casefold=True)

output = b16encode(xor(input1_bytes, input2_bytes)).lower()

assert output == expected_output
print("[+] Comparison Successfull!")
