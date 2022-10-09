import socket
import threading
import json
from cryptopals_utils import pkcs7_unpad, pkcs7_pad
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Random.random import choice
from base64 import b64decode

PORT = 13370
HOST = socket.gethostbyname(socket.gethostname())
ADDR = (HOST, PORT)

server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.bind(ADDR)


key = get_random_bytes(16)

def encrypt_message():
    msgs = [b"MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=", b"MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic=", b"MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw==", b"MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg==", b"MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl", b"MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA==", b"MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw==", b"MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8=", b"MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g=", b"MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93"]
    msgs_bytes = [b64decode(msg) for msg in msgs]
    iv = get_random_bytes(16)
    cipher = AES.new(key, AES.MODE_CBC, iv=iv)
    pt = pkcs7_pad(choice(msgs_bytes))
    ct = cipher.encrypt(pt)
    return iv, ct

def validate_padding(iv, ct):
    cipher = AES.new(key, AES.MODE_CBC, iv=iv)
    pt = cipher.decrypt(ct)
    try:
        pkcs7_unpad(pt)
        return True
    except:
        return False

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
            elif cmd == "!GET_CT":
                iv, ct = encrypt_message()
                send(conn, {"iv": iv.hex(), "ct": ct.hex()})
            elif cmd == "!VALIDATE":
                iv = bytes.fromhex(msg['iv'])
                ct = bytes.fromhex(msg['ct'])
                send(conn, {"response": validate_padding(iv, ct)})

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
