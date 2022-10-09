import socket
import json
from cryptopals_utils import xor

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

def get_iv_ct_pair():
    send({'cmd': "!GET_CT"})
    received = recv()
    return bytes.fromhex(received['iv']), bytes.fromhex(received['ct'])

def validate(iv, ct):
    send({'cmd': "!VALIDATE", 'iv': iv.hex(), 'ct': ct.hex()})
    return recv()['response']


iv, ct = get_iv_ct_pair()

intermediate_blocks = []
ciphertext_blocks = [ct[i:i+16] for i in range(0, len(ct), 16)]
for block in ciphertext_blocks:
    fake_iv = list(b'\x00'*16)
    intermediate_block = list(b'\x00'*16)
    for work_byte_idx in range(15, -1, -1):
        for i in range(256):
            padbyte = 16 - work_byte_idx
            for j in range(work_byte_idx+1, 16):
                fake_iv[j] = intermediate_block[j] ^ padbyte

            fake_iv[work_byte_idx] = i
            if validate(bytes(fake_iv), block):
                intermediate_block[work_byte_idx] = i ^ padbyte
                break
    intermediate_blocks.append(bytes(intermediate_block))

plaintext_blocks = []
for idx in range(len(ciphertext_blocks)):
    if idx == 0:
        plaintext_blocks.append(xor(iv, intermediate_blocks[0]))
    else:
        plaintext_blocks.append(xor(ciphertext_blocks[idx-1], intermediate_blocks[idx]))
plaintext = b''.join(plaintext_blocks)

print("[+] PLAINTEXT is:")
print(plaintext)

send({'cmd': "!DISCONNECT"})
