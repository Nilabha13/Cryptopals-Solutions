from cryptopals_utils import MT19937
from Crypto.Random.random import randrange


#==============================

r_original = MT19937(randrange(10**8))
original_outputs = [r_original.random() for i in range(624)]

#==============================



def untemper(y):
    def untemper_unit(y, M, s, shiftdir):
        def get_bitlist(num):
            bitlist_inter = [int(bit) for bit in bin(num)[2:]]
            return [0]*(32 - len(bitlist_inter)) + bitlist_inter

        y_bits, M_bits = get_bitlist(y), get_bitlist(M)
        x_bits = [0]*32
        if shiftdir == "left":
            for idx in range(31, 32-s-1, -1):
                x_bits[idx] = y_bits[idx]
            for idx in range(32-s-1, -1, -1):
                x_bits[idx] = y_bits[idx] ^ (x_bits[idx+s] & M_bits[idx])
        elif shiftdir == "right":
            for idx in range(s):
                x_bits[idx] = y_bits[idx]
            for idx in range(s, 32):
                x_bits[idx] = y_bits[idx] ^ (x_bits[idx-s] & M_bits[idx])
        x = int(''.join(str(bit) for bit in x_bits), 2)
        return x
    
    u, d = 11, 0xffffffff
    s, b = 7, 0x9d2c5680
    t, c = 15, 0xefc60000
    l = 18
    y3 = untemper_unit(y, (1 << 32) - 1, l, "right")
    y2 = untemper_unit(y3, c, t, "left")
    y1 = untemper_unit(y2, b, s, "left")
    y0 = untemper_unit(y1, d, u, "right")

    return y0

def recover_state(output_list):
    return [untemper(output) for output in output_list]

state = recover_state(original_outputs)
r_fake = MT19937()
r_fake._MT = state


try:
    for i in range(624*100):
        assert r_original.random() == r_fake.random()
    print("[+] Successfully predicted all values of PRNG!")
except:
    print("[-] Failure! Could not predict all values of PRNG!")
