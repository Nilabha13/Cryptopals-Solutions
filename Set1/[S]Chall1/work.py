from base64 import b16decode, b64encode

input = b'49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d'
expected_output =  b'SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t'

output = b64encode(b16decode(input, casefold=True))

assert output == expected_output
print("[+] Comparison Successfull!")
