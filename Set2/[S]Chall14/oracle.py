import socket
import threading
import json
from base64 import b64decode
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES
from cryptopals_utils import pkcs7_pad
from Crypto.Random.random import randrange

PORT = 13370
HOST = socket.gethostbyname(socket.gethostname())
ADDR = (HOST, PORT)

server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.bind(ADDR)

secret = b"Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK"
secret_bytes = b64decode(secret)
prefix = get_random_bytes(randrange(50))

key = get_random_bytes(16)
def encrypt(input_bytes):
    message = pkcs7_pad(prefix + input_bytes + secret_bytes)
    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.encrypt(message)


def send(conn, msg):
    print(f"[RESPONSE] {msg}")
    message = json.dumps(msg).encode()
    conn.send(message)

def handle_client(conn, addr):
    print(f"[NEW CONNECTION] {addr} connected")

    connected = True
    mode = None
    while connected:
        msg = json.loads(conn.recv(2048).decode())
        if msg:
            print(f"[{addr}] {msg}")
            cmd = msg['cmd']
            if cmd == "!DISCONNECT":
                connected = False
                send(conn, {"response": "Disconnected"})
            elif cmd == "!ENCRYPT":
                pt = bytes.fromhex(msg['pt'])
                ct = encrypt(pt)
                send(conn, {"response": ct.hex()})
    conn.close()
    server.close()


def start():
    server.listen()
    print(f"[LISTENING] Server is listening on {HOST}")
    while True:
        conn, addr = server.accept()
        thread = threading.Thread(target=handle_client, args=(conn, addr))
        thread.start()
        print(f"[ACTIVE CONNECTIONS] {threading.activeCount() - 1}")


print("[STARTING] Server is starting...")
start()
