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
chunk1 = oracle(b'A')
chunk2 = oracle(b'B')
prefix_block_fill_count = 0
while chunk1[prefix_block_fill_count] == chunk2[prefix_block_fill_count]:
    prefix_block_fill_count += 1
prefix_fake_count = 1
while oracle(b'A'*prefix_fake_count)[prefix_block_fill_count] != oracle(b'A'*(prefix_fake_count+1))[prefix_block_fill_count]:
    prefix_fake_count += 1
chunk1 = oracle(b'A'*prefix_fake_count)
chunk2 = oracle(b'A'*(prefix_fake_count+1))
prefix_fake_block_fill_count = 0
while chunk1[prefix_fake_block_fill_count] == chunk2[prefix_fake_block_fill_count]:
    prefix_fake_block_fill_count += 1
BLOCK_SIZE = prefix_fake_block_fill_count - prefix_block_fill_count
FAKE_PREFIX = b'A'*prefix_fake_count
NUM_PREFIX_BLOCKS = prefix_fake_block_fill_count//BLOCK_SIZE
print(f"[!] BLOCK_SIZE found: {BLOCK_SIZE}")


#Siege 2: Detect if ECB being used
assert detect_aes_ecb(oracle(b'A'*(3*BLOCK_SIZE)), BLOCK_SIZE) == True
print("[!] AES_ECB is being used!")


#Siege 3: Nail that secret string!
num_blocks_secret = len(oracle(FAKE_PREFIX)[NUM_PREFIX_BLOCKS*BLOCK_SIZE:])//BLOCK_SIZE
secret = b''
for count in range(1, num_blocks_secret*BLOCK_SIZE+1):
    payload = FAKE_PREFIX + b'A'*(num_blocks_secret*BLOCK_SIZE - count)
    chunk = oracle(payload)[NUM_PREFIX_BLOCKS*BLOCK_SIZE : NUM_PREFIX_BLOCKS*BLOCK_SIZE+num_blocks_secret*BLOCK_SIZE]
    for i in range(256):
        chunk_guess = oracle(payload + secret + chr(i).encode())[NUM_PREFIX_BLOCKS*BLOCK_SIZE : NUM_PREFIX_BLOCKS*BLOCK_SIZE+num_blocks_secret*BLOCK_SIZE]
        if chunk == chunk_guess:
            secret += chr(i).encode()
            break

try:
    print(f"[!] SECRET found: {secret.decode()}")
except:
    print("[-] SECRET not expressible in ASCII! Invalid SECRET!")


#Disconnect
send({'cmd': "!DISCONNECT"})
