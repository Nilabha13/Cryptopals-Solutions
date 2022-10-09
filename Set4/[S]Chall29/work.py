from Crypto.Util.number import long_to_bytes
from random import choice

def sha1(data, h0=0x67452301, h1=0xEFCDAB89, h2=0x98BADCFE, h3=0x10325476, h4=0xC3D2E1F0, prev_len=0):
    bytesVar = ""

    for n in range(len(data)):
        bytesVar+='{0:08b}'.format(data[n])
    bits = bytesVar+"1"
    pBits = bits
    #pad until length equals 448 mod 512
    while len(pBits)%512 != 448:
        pBits+="0"
    #append the original length
    pBits+='{0:064b}'.format(prev_len*8 + len(bits)-1)
    
    def chunks(l, n):
        return [l[i:i+n] for i in range(0, len(l), n)]

    def rol(n, b):
        return ((n << b) | (n >> (32 - b))) & 0xffffffff

    for c in chunks(pBits, 512): 
        words = chunks(c, 32)
        w = [0]*80
        for n in range(0, 16):
            w[n] = int(words[n], 2)
        for i in range(16, 80):
            w[i] = rol((w[i-3] ^ w[i-8] ^ w[i-14] ^ w[i-16]), 1)  

        a = h0
        b = h1
        c = h2
        d = h3
        e = h4

        #Main loop
        for i in range(0, 80):
            if 0 <= i <= 19:
                f = (b & c) | ((~b) & d)
                k = 0x5A827999
            elif 20 <= i <= 39:
                f = b ^ c ^ d
                k = 0x6ED9EBA1
            elif 40 <= i <= 59:
                f = (b & c) | (b & d) | (c & d) 
                k = 0x8F1BBCDC
            elif 60 <= i <= 79:
                f = b ^ c ^ d
                k = 0xCA62C1D6

            temp = rol(a, 5) + f + e + k + w[i] & 0xffffffff
            e = d
            d = c
            c = rol(b, 30)
            b = a
            a = temp

        h0 = h0 + a & 0xffffffff
        h1 = h1 + b & 0xffffffff
        h2 = h2 + c & 0xffffffff
        h3 = h3 + d & 0xffffffff
        h4 = h4 + e & 0xffffffff

    return '%08x%08x%08x%08x%08x' % (h0, h1, h2, h3, h4)


def glue_padding(len_prefix, msg):
    data_len = (len_prefix + len(msg))*8
    padBits = "1"
    while (data_len + len(padBits))%512 != 448:
        padBits += "0"
    padBits+='{0:064b}'.format(data_len)
    return long_to_bytes(int(padBits,2))


#=====
key = choice([line.strip() for line in open("/usr/share/dict/words", 'r').readlines()]).encode()
def mac(data):
    return sha1(key + data)
#=====


msg = b"comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon"
#=====
mac_msg = mac(msg)
#=====

key_len = 0
while True:
    fake_data = msg + glue_padding(key_len, msg) + b";admin=true"
    #=====
    actual_mac = mac(fake_data)
    #=====
    h0, h1, h2, h3, h4 = [int(mac_msg[i:i+8], 16) for i in range(0, 40, 8)]
    fake_mac = sha1(b";admin=true", h0, h1, h2, h3, h4, key_len+len(msg + glue_padding(key_len, msg)))

    if actual_mac == fake_mac:
        print(fake_mac)
        print("[+] MAC Successfully Forged!")
        break

    key_len += 1
