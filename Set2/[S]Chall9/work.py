input = b"YELLOW SUBMARINE"
expected_output = b"YELLOW SUBMARINE\x04\x04\x04\x04"

def pkcs7_pad(byte_string, BLOCK_SIZE=16):
    pad_num = BLOCK_SIZE - (len(byte_string)%BLOCK_SIZE)
    return byte_string + chr(pad_num).encode()*pad_num

assert pkcs7_pad(input, 20) == expected_output
print("[+] Comparison Successfull!")
