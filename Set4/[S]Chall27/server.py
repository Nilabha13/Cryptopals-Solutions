import socket
import threading
import json
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

PORT = 13370
HOST = socket.gethostbyname(socket.gethostname())
ADDR = (HOST, PORT)

server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.bind(ADDR)


key = get_random_bytes(16)

def encrypt(data):
    cipher = AES.new(key, AES.MODE_CBC, iv=key)
    return cipher.encrypt(data)

def decrypt(data):
    cipher = AES.new(key, AES.MODE_CBC, iv=key)
    return cipher.decrypt(data)

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
                send(conn, {"response": encrypt(pt).hex()})
            elif cmd == "!RECEIVE":
                ct = bytes.fromhex(msg['ct'])
                try:
                    decrypt(ct).decode()
                    send(conn, {"response": "Received! OK!"})
                except:
                    send(conn, {"error": "Invalid ciphertext!", "response": decrypt(ct).hex()})
            elif cmd == "!CHECK_KEY":
                k = bytes.fromhex(msg['key'])
                send(conn, {"response": k == key})
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
