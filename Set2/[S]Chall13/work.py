import socket
import json
from cryptopals_utils import pkcs7_pad

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
    
def profile_for(email):
    send({'cmd': "!CREATEPROFILE", 'email': email.hex()})
    return bytes.fromhex(recv()["response"])
	
def authenticate(token):
    send({'cmd': "!AUTHENTICATE", 'token': token.hex()})
    return recv()["response"]
	

token = profile_for(b"prohecker1337@hackermail.com")
print(f"AUTHENTICATION TRIAL: {authenticate(token)}")

fake_block = b"A"*10 + pkcs7_pad(b"admin")
fake_token_block = profile_for(fake_block)[16:32]

malicious_token = profile_for(b"A"*13)[:32] + fake_token_block

if authenticate(malicious_token) == True:
    print("[+] Authentication successfull! You've successfully hacked in!")
else:
    print("[-] Authentication failed!")

send({'cmd': "!DISCONNECT"})
