class MT19937:
    def __init__(self, seed=5489):
        self._w, self._n, self._m, self._r = 32, 624, 397, 31
        self._a = 0x9908b0df
        self._u, self._d = 11, 0xffffffff
        self._s, self._b = 7, 0x9d2c5680
        self._t, self._c = 15, 0xefc60000
        self._l = 18
        self._f = 1812433253

        self._MT = [0]*self._n
        self._index = self._n+1
        self._lower_mask = (1 << self._r) - 1
        self._upper_mask = ((1 << self._w) - 1) - self._lower_mask

        self._seed_mt(seed)

    def _seed_mt(self, seed):
        self._index = self._n
        self._MT[0] = seed & ((1 << self._w) - 1)
        for i in range(1, self._n):
            self._MT[i] = (self._f * (self._MT[i-1] ^ (self._MT[i-1] >> (self._w - 2))) + i) & ((1 << self._w) - 1)

    def _twist(self):
        for i in range(self._n):
            x = (self._MT[i] & self._upper_mask) + (self._MT[(i+1) % self._n] & self._lower_mask)
            xA = x >> 1
            if x%2 != 0:
                xA = xA ^ self._a
            self._MT[i] = self._MT[(i+self._m)%self._n] ^ xA
        self._index = 0

    def random(self):
        if self._index == self._n:
            self._twist()

        y = self._MT[self._index]
        y = y ^ ((y >> self._u) & self._d)
        y = y ^ ((y << self._s) & self._b)
        y = y ^ ((y << self._t) & self._c)
        y = y ^ (y >> self._l)

        self._index = self._index + 1
        return y & ((1 << self._w) - 1)



filename = "21.txt"
nums = [int(line.strip()) for line in open(filename, 'r').readlines()]

r = MT19937()
for num in nums:
    assert num == r.random()

print("[+] MT19937 implementation working successfully!")
