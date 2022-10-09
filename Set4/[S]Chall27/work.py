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


payload = b"A"*16 + b"B"*16 + b"C"*16
send({'cmd': "!ENCRYPT", 'pt': payload.hex()})
ciphertext = bytes.fromhex(recv()['response'])

fake_ciphertext = ciphertext[:16] + b'\x00'*16 + ciphertext[:16]
send({'cmd': "!RECEIVE", 'ct': fake_ciphertext.hex()})
response = recv()

try:
    assert "error" in response
    error_plaintext = bytes.fromhex(response['response'])
    pt1, pt3 = error_plaintext[:16], error_plaintext[32:]
    key = xor(pt1, pt3)

    send({'cmd': "!CHECK_KEY", 'key': key.hex()})
    if recv()['response'] == True:
        print("[+] Key successfully found!")
        print(f"KEY: {key}")
    else:
        print("[-] Key not found!")
except:
    print("[-] Ciphertext mangling failed!")

send({'cmd': "!DISCONNECT"})
