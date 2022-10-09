import socket
import threading
import json
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Random.random import randrange
from cryptopals_utils import pkcs7_pad

PORT = 13370
HOST = socket.gethostbyname(socket.gethostname())
ADDR = (HOST, PORT)

server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.bind(ADDR)

def encrypt(pt):
    random_count = randrange(5, 11)
    pt = pkcs7_pad(get_random_bytes(random_count) + pt + get_random_bytes(random_count))
    key = get_random_bytes(16)
    choice = randrange(2)
    if choice == 0:
        cipher = AES.new(key, AES.MODE_ECB)
        return "ECB", cipher.encrypt(pt)
    else:
        iv = get_random_bytes(16)
        cipher = AES.new(key, AES.MODE_CBC, iv=iv)
        return "CBC", cipher.encrypt(pt)


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
                mode, ct = encrypt(pt)
                send(conn, {"response": ct.hex()})
            elif cmd == "!VERIFY":
                verify_token = msg['verify_token']
                verify_status = False
                if verify_token == mode:
                    verify_status = True
                send(conn, {"response": verify_status})
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



