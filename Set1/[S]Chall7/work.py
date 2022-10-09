from base64 import b64decode
from Crypto.Cipher import AES

filename = "7.txt"
input = open(filename, 'r').read().replace('\n', '').encode()
key = b'YELLOW SUBMARINE'

input_bytes = b64decode(input)
cipher = AES.new(key, AES.MODE_ECB)

pt = cipher.decrypt(input_bytes)

try:
	print(pt.decode())
except:
	print("[-] ERROR: Decryption not expressible in ASCII! Invalid decryption!")
