def pkcs7_unpad(byte_string, BLOCK_SIZE=16):
	if len(byte_string) < BLOCK_SIZE:
		raise Exception("Incorrect Padding!")
	padbyte = byte_string[-1]
	if padbyte > BLOCK_SIZE:
		raise Exception("Incorrect Padding!")
	if byte_string[-padbyte:] != chr(padbyte).encode()*padbyte:
		raise Exception("Incorrect Padding!")
	return byte_string[:-padbyte]



assert pkcs7_unpad(b"ICE ICE BABY\x04\x04\x04\x04") == b"ICE ICE BABY"
print("[+] Check 1/3 passed!")

try:
	pkcs7_unpad(b"ICE ICE BABY\x05\x05\x05\x05")
except Exception as e:
	print(e)
	print("[+] Check 2/3 passed!")

try:
	pkcs7_unpad(b"ICE ICE BABY\x01\x02\x03\x04")
except Exception as e:
        print(e)
        print("[+] Check 3/3 passed!")
