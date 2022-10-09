import socket
import threading
import json
from cryptopals_utils import pkcs7_pad, pkcs7_unpad
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Random.random import randrange

PORT = 13370
HOST = socket.gethostbyname(socket.gethostname())
ADDR = (HOST, PORT)

server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.bind(ADDR)

def parse(query_string):
	key_vals = query_string.split(b'&')
	obj = {}
	for key_val in key_vals:
		k, v = key_val.split(b'=')
		obj[k] = v
	return obj

key = get_random_bytes(16)

def encrypt(pt):
	cipher = AES.new(key, AES.MODE_ECB)
	return cipher.encrypt(pkcs7_pad(pt))
	
def decrypt(ct):
	cipher = AES.new(key, AES.MODE_ECB)
	return pkcs7_unpad(cipher.decrypt(ct))

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
			elif cmd == "!CREATEPROFILE":
				email = bytes.fromhex(msg['email']).replace(b'&', b'').replace(b'=', b'')
				encoding = b"email=" + email + f"&uid={randrange(10,100)}&role=user".encode()
				token = encrypt(encoding)
				send(conn, {"response": token.hex()})
			elif cmd == "!AUTHENTICATE":
				token = bytes.fromhex(msg['token'])
				encoding = decrypt(token)
				parsed_token = parse(encoding)
				if b'role' in parsed_token and parsed_token[b'role'] == b'admin':
					send(conn, {"response": True})
				else:
					send(conn, {"response": False})
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
