import socket
import json
from cryptopals_utils import detect_aes_ecb

PORT = 13370
HOST = "127.0.1.1"
ADDR = (HOST, PORT)

client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client.connect(ADDR)

def send(msg):
    message = json.dumps(msg).encode()
    client.send(message)

def recv():
    return json.loads(client.recv(2048).decode())

def oracle(pt):
    send({'cmd': "!ENCRYPT", 'pt': pt.hex()})
    return bytes.fromhex(recv()['response'])


#Siege 1: Discover BLOCK_SIZE
blocksize_guess = 1
while True:
    if oracle(b'A'*blocksize_guess)[:blocksize_guess] == oracle(b'A'*(blocksize_guess+1))[:blocksize_guess]:
        BLOCK_SIZE = blocksize_guess
        break
    blocksize_guess += 1
print(f"[!] BLOCK_SIZE found: {BLOCK_SIZE}")


#Siege 2: Detect if ECB being used
assert detect_aes_ecb(oracle(b'A'*(3*BLOCK_SIZE)), BLOCK_SIZE) == True
print("[!] AES_ECB is being used!")


#Siege 3: Nail that secret string!
num_blocks_secret = len(oracle(b''))//BLOCK_SIZE
secret = b''
for count in range(1, num_blocks_secret*BLOCK_SIZE+1):
    payload = b'A'*(num_blocks_secret*BLOCK_SIZE - count)
    chunk = oracle(payload)[:num_blocks_secret*BLOCK_SIZE]
    for i in range(256):
        chunk_guess = oracle(payload + secret + chr(i).encode())[:num_blocks_secret*BLOCK_SIZE]
        if chunk == chunk_guess:
            secret += chr(i).encode()
            break

try:
    print(f"[!] SECRET found: {secret.decode()}")
except:
    print("[-] SECRET not expressible in ASCII! Invalid SECRET!")


#Disconnect
send({'cmd': "!DISCONNECT"})
