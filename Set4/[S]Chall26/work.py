import socket
import json

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

def generate_token(data):
    send({'cmd': "!GEN_TOKEN" ,'data': data.hex()})
    return bytes.fromhex(recv()['response'])

def authenticate(token):
    send({'cmd': "!AUTHENTICATE", 'token': token.hex()})
    return recv()['response']


prefix = b"comment1=cooking%20MCs;userdata="
suffix = b";comment2=%20like%20a%20pound%20of%20bacon"

len_prefix = len(prefix)
len_suffix = len(suffix)

payload = b"_admin_true_"
token = generate_token(payload)

start_idx = len_prefix
fake_token = list(token)
fake_token[start_idx + 0] = fake_token[start_idx + 0] ^ ord('_') ^ ord(';') 
fake_token[start_idx + 6] = fake_token[start_idx + 6] ^ ord('_') ^ ord('=') 
fake_token[start_idx + 11] = fake_token[start_idx + 11] ^ ord('_') ^ ord(';') 
fake_token = bytes(fake_token)

if authenticate(fake_token) == True:
    print("[+] SUCCESS! Authentication successfull!")
else:
    print("[-] FAILURE! Authentication failed!")


send({'cmd': "!DISCONNECT"})
