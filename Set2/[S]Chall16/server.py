import socket
import threading
import json
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from cryptopals_utils import pkcs7_pad, pkcs7_unpad

PORT = 13370
HOST = socket.gethostbyname(socket.gethostname())
ADDR = (HOST, PORT)

server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.bind(ADDR)


key = get_random_bytes(16)
iv = get_random_bytes(16)

def generate_token(data):
    cipher = AES.new(key, AES.MODE_CBC, iv=iv)
    prefix = b"comment1=cooking%20MCs;userdata="
    suffix = b";comment2=%20like%20a%20pound%20of%20bacon"
    data_full = prefix + data.replace(b";", b"';'").replace(b"=", b"'='") + suffix
    data_full_padded = pkcs7_pad(data_full)
    return cipher.encrypt(data_full_padded)

def authenticate(token):
    cipher = AES.new(key, AES.MODE_CBC, iv=iv)
    data = pkcs7_unpad(cipher.decrypt(token))
    if b";admin=true;" in data:
        return True
    else:
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
            elif cmd == "!GEN_TOKEN":
                data = bytes.fromhex(msg['data'])
                token = generate_token(data)
                send(conn, {"response": token.hex()})
            elif cmd == "!AUTHENTICATE":
                token = bytes.fromhex(msg['token'])
                status = authenticate(token)
                send(conn, {"response": status})
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
