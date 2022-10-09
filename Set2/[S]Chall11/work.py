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

def encryption_oracle(pt):
    send({'cmd': "!ENCRYPT", 'pt': pt.hex()})
    return bytes.fromhex(recv()['response'])

def verify(mode_guess):
    send({'cmd': "!VERIFY", 'verify_token': mode_guess})
    return recv()['response']


NUM_TRIALS = 100
num_successes = 0
for i in range(NUM_TRIALS):
    payload = b"A"*100
    ct = encryption_oracle(payload)
    if detect_aes_ecb(ct) == True:
        num_successes += int(verify("ECB"))
    else:
        num_successes += int(verify("CBC"))
print(f"[!] {num_successes} / {NUM_TRIALS} guesses correct!")
print(f"[!] ACCURACY: {num_successes/NUM_TRIALS * 100}%")

send({'cmd': "!DISCONNECT"})
