from itertools import cycle
from base64 import b16encode

input = b"Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal"
expected_output = b"0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f"
key = b"ICE"

def repeat_xor(key, byte_string):
	return bytes(c1^c2 for (c1, c2) in zip(byte_string, cycle(key)))


output = b16encode(repeat_xor(key, input)).lower()

assert output == expected_output
print("[+] Comparison Successfull!")
