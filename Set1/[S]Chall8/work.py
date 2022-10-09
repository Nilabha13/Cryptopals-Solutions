from base64 import b16decode

filename = "8.txt"
input = [line.strip() for line in open(filename, 'r').readlines()]

input_bytes = [b16decode(line, casefold=True) for line in input]

def detect_aes_ecb(byte_string, BLOCK_SIZE=16):
	chunks = [byte_string[i:i+BLOCK_SIZE] for i in range(0, len(byte_string), BLOCK_SIZE)]
	uniq_chunks = set(chunks)
	return True if len(chunks) != len(uniq_chunks) else False


for line_num in range(len(input_bytes)):
	if detect_aes_ecb(input_bytes[line_num]):
		print(f"Line Number {line_num+1} is possibly encrypted using AES_ECB!")
		print(f"Ciphertext: {input[line_num]}")
