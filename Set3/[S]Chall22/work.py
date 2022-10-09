from cryptopals_utils import MT19937
from time import time, sleep
from random import randrange

def routine():
    sleep(randrange(40, 1000))
    SEED = int(time())
    r = MT19937(SEED)
    sleep(randrange(40, 1000))
    return SEED, r.random()

#==============================

print("Running routine()...")
SEED, output = routine()
print(f"[!] PRNG ouptut: {output}")

print("[!] Cracking PRNG seed")
seed = int(time())
while True:
    r = MT19937(seed)
    if r.random() == output:
        break
    seed -= 1

try:
    assert seed == SEED
    print(f"[+] PRNG cracked! seed={seed}")
except:
    print("[-] Invalid PRNG cracking! Incorrect seed!")
