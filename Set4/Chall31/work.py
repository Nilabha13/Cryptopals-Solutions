import requests
from datetime import datetime

url = "http://0.0.0.0:8080/test"
file_contents = b"I am a file!"

forged_sig = b""
for i in range(20):
    for char_guess in range(256):
        t1 = datetime.now()
        sig = forged_sig + chr(char_guess).encode()
        requests.get(url, {"file": file_contents.hex(), "signature": sig.hex()})
        t2 = datetime.now()
        if (t2-t1).microseconds/1000 >= 50:
            forged_sig += chr(char_guess).encode()
            print(f"[+] Partial forge: {forged_sig.hex()}")
            break

print(f"[+] Signature forged: {forged_sig.hex()}")

if requests.get(url, {"file": file_contents.hex(), "signature": forged_sig.hex()}).text.strip().endswith("400"):
    print("[+] Signature Successfully Forged!")
else:
    print("[-] Incorrect Signature Forged!")
