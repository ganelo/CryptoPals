#!/usr/bin/python
from array import array

class AES:
    MODE_ECB = 1
    MODE_CBC = 2
    MODE_CFB = 3
    MODE_PGP = 4
    MODE_OFB = 5
    MODE_CTR = 6

    sfor = [0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01,
            0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76, 0xCA, 0x82, 0xC9, 0x7D,
            0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4,
            0x72, 0xC0, 0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC,
            0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15, 0x04, 0xC7,
            0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2,
            0xEB, 0x27, 0xB2, 0x75, 0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E,
            0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
            0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB,
            0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF, 0xD0, 0xEF, 0xAA, 0xFB,
            0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C,
            0x9F, 0xA8, 0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5,
            0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2, 0xCD, 0x0C,
            0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D,
            0x64, 0x5D, 0x19, 0x73, 0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A,
            0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
            0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3,
            0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79, 0xE7, 0xC8, 0x37, 0x6D,
            0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A,
            0xAE, 0x08, 0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6,
            0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A, 0x70, 0x3E,
            0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9,
            0x86, 0xC1, 0x1D, 0x9E, 0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9,
            0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
            0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99,
            0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16]

    srev = [0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40,
            0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB, 0x7C, 0xE3, 0x39, 0x82,
            0x9B, 0x2F, 0xFF, 0x87, 0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE,
            0xE9, 0xCB, 0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D,
            0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E, 0x08, 0x2E,
            0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2, 0x76, 0x5B, 0xA2, 0x49,
            0x6D, 0x8B, 0xD1, 0x25, 0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68,
            0x98, 0x16, 0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92,
            0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA, 0x5E, 0x15,
            0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84, 0x90, 0xD8, 0xAB, 0x00,
            0x8C, 0xBC, 0xD3, 0x0A, 0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3,
            0x45, 0x06, 0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02,
            0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B, 0x3A, 0x91,
            0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA, 0x97, 0xF2, 0xCF, 0xCE,
            0xF0, 0xB4, 0xE6, 0x73, 0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD,
            0x35, 0x85, 0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E,
            0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89, 0x6F, 0xB7,
            0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B, 0xFC, 0x56, 0x3E, 0x4B,
            0xC6, 0xD2, 0x79, 0x20, 0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD,
            0x5A, 0xF4, 0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31,
            0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F, 0x60, 0x51,
            0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D, 0x2D, 0xE5, 0x7A, 0x9F,
            0x93, 0xC9, 0x9C, 0xEF, 0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A,
            0xF5, 0xB0, 0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61,
            0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26, 0xE1, 0x69,
            0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D]

    def __init__(self, key, mode=MODE_ECB, init_vector=None, counter=None):
        # def counter():
        #     i = 0
        #     while True:
        #         yield "%016x" % i
        #         i += 1
        # Note: to decrypt in CTR mode, make sure you have the same counter
        #       value as when the ciphertext was encrypted (easiest to achieve
        #       by creating one 'encrypting' AES instance and one 'decrypting'
        #       instance so their counters increment in parallel.
        if not self.MODE_ECB <= mode <= self.MODE_CTR:
            raise ValueError("Unknown cipher mode.")
        if mode == self.MODE_PGP:
            raise NotImplementedError("PGP mode is intentionally unimplemented due to insecurity.  Don't use it.")

        self.key = array('B', key)
        self.mode = mode
        self.init_vector = array('B', init_vector or [])
        self.counter = counter

        if len(self.key)*8 not in [128, 192, 256]:
            raise ValueError("AES requires 128-, 192-, or 256-bit keys")
        if len(self.init_vector) not in [0, 16]:
            raise ValueError("Initialization Vector must be 16 bytes long")
        if self.mode == self.MODE_CTR and not callable(counter):
            raise ValueError("Counter must be present and callable when using CTR mode")

        self.cycles = {128: 10, 192: 12, 256: 14}[len(self.key)*8]
        self.n      = {128: 16, 192: 24, 256: 32}[len(self.key)*8]
        self.b      = {128:176, 192:208, 256:240}[len(self.key)*8]

    def _rotate(self, arr, times=1):
        if times == 0:
            return arr
        else:
            return self._rotate(arr[1:] + array('B', [arr[0]]), times-1)

    def _core(self, word, iteration):
        # Rotate
        word = self._rotate(word)
        # S-box
        word = map(lambda b: self.sfor[b], word)
        # XOR 1st byte w/ rcon(iteration)
        word[0] ^= self._rcon(iteration)
        return array('B', word)

    def _xor(self, seqa, seqb):
        return array('B', map(lambda (a, b): a^b, zip(seqa, seqb))) 

    def _expand(self):
        # The first n bytes are the original encryption key
        key = array('B', self.key)

        i = 1
        while len(key) < self.b:
            # 4 bytes
            t = self._core(key[-4:], i)
            i += 1
            key.extend(self._xor(t, key[-1*self.n:-1*self.n+4]))

            # 12 bytes
            for _ in range(3):
                key.extend(self._xor(key[-4:], key[-1*self.n:-1*self.n+4]))
            
            # 0, 0, or 4 bytes
            if len(self.key)*8 == 256:
                key.extend(self._xor(map(lambda b: self.sfor[b], key[-4:]),
                                     key[-1*self.n:-1*self.n+4]))

            # 0, 8, or 12 bytes
            if len(self.key)*8 == 128:
                continue
            for x in range(3):
                if x == 2 and len(self.key)*8 == 192:
                    break
                key.extend(self._xor(key[-4:], key[-1*self.n:-1*self.n+4]))
        return key

    def _shift_rows(self, state, reverse=False):
        for row in range(4):
            #each row shifts by <row> bytes
            tos = array('B', range(row, 16, 4))
            frs = self._rotate(tos, row if not reverse else 4-row)
            temp = state[:]
            for to, fr in zip(tos, frs):
                state[to] = temp[fr]
        return state

    def _mix_columns(self, state):
        blocks = [state[i:i+4] for i in range(0, len(state), 4)]
        for i, block in enumerate(blocks):
            a = block[:]
            # b = gmul(e, 2) for e in a
            # b/c we're using 2 and 3, we can special case instead of
            # calling _gmul
            b = [((c << 1) & 0xff) ^ (0x1b if (c & 0x80) else 0)
                     for c in block]
            state[i*4:(i+1)*4] = array('B', [b[n]^b[n-3]^a[n-3]^a[n-2]^a[n-1]
                                                 for n in range(4)])
        return state

    def _gmul(self, a, b):
        p = 0
        for _ in range(8):
            p ^= a if b & 1 else 0
            a = ((a << 1) & 0xff) ^ (0x1b if (a & 0x80) else 0)
            b >>= 1
        return p

    def _rcon(self, i):
        if i <= 2:
            return i
        return self._gmul(2, self._rcon(i-1))

    def _inv_mix_columns(self, state):
        blocks = [state[i:i+4] for i in range(0, len(state), 4)]
        for i, block in enumerate(blocks):
            a = block[:]
            b = array('B', [14, 11, 13, 9])
            for n in range(4):
                state[i*4+n] = (self._gmul(a[0], b[0]) ^
                                self._gmul(a[1], b[1]) ^
                                self._gmul(a[2], b[2]) ^
                                self._gmul(a[3], b[3]))
                b = self._rotate(b, 3)
            
        return state

    def _encrypt(self, state, round_keys):
        state = self._xor(state, round_keys[0])
        for i in range(self.cycles-1):
            key = round_keys[i+1]
            state = array('B',map(lambda b: self.sfor[b], state))
            state = self._shift_rows(state)
            state = self._mix_columns(state)
            state = self._xor(state, key)
        key = round_keys[self.cycles]
        state = array('B',map(lambda b: self.sfor[b], state))
        state = self._shift_rows(state)
        state = self._xor(state, key)
        return state

    def _decrypt(self, state, round_keys):
        key = round_keys[self.cycles]
        # xor is directionless
        state = self._xor(state, key)
        state = self._shift_rows(state, reverse=True)
        state = array('B', map(lambda b: self.srev[b], state))
        for i in range(self.cycles-1):
            key = round_keys[self.cycles-1-i]
            state = self._xor(state, key)
            state = self._inv_mix_columns(state)
            state = self._shift_rows(state, reverse=True)
            state = array('B', map(lambda b: self.srev[b], state))
        state = self._xor(state, round_keys[0])
        return state

    def encrypt(self, plaintext):
        plain = array('B', plaintext)
        blocks = [plain[i*16:(i+1)*16] for i in range(len(plain)/16)]
        key = self._expand()
        round_keys = [key[i*16:(i+1)*16] for i in range(len(key)/16)]
        cipher = array('B')
        last = self.init_vector
        if self.mode == self.MODE_CTR:
            # We use Nonce concatenated with CTR
            last.extend(array('B', self.counter()))
        for state in blocks:
            if self.mode == self.MODE_CBC:
                # CBC requires XORing with the last cipher block
                # (starting with the init_vector) before encryption
                state = self._xor(state, last)
            elif self.mode in [self.MODE_CFB,
                               self.MODE_OFB,
                               self.MODE_CTR]:
                # CDB and OFB require encrypting the init_vector
                # and XORing that with the plaintext; CTR does the
                # same with the counter combined with the init_vector
                block = state
                state = last

            state = self._encrypt(state, round_keys)

            if self.mode == self.MODE_OFB:
                # OFB requires continuing to re-encrypt the IV
                # over and over again, without XORing it with
                # anything first (unlike CFB, which takes the
                # encrypted IV post-XORing with plaintext as
                # input to the next block)
                last = state
            elif self.mode == self.MODE_CTR:
                last = last[16:]
                if len(last) < 16:
                    last += self.init_vector + self.counter()
            if self.mode in [self.MODE_CFB,
                             self.MODE_OFB,
                             self.MODE_CTR]:
                state = self._xor(state, block)
            if self.mode != self.MODE_OFB:
                last = state

            cipher.extend(state)
        # int div is truncated, so this is different from plain[len(plain):]
        left_over = plain[len(plain)/16*16:]
        if left_over and self.mode == self.MODE_CTR:
            while len(left_over) > len(last):
                last += self.init_vector + self.counter()
            state = self._encrypt(last, round_keys)
            state = self._xor(state, left_over)
            cipher.extend(state)
        return cipher.tostring()

    def decrypt(self, ciphertext):
        if self.mode in [self.MODE_OFB,
                         self.MODE_CTR]:
            # OFB and CTR decryption and encryption are identical
            return self.encrypt(ciphertext)
        cipher = array('B', ciphertext)
        blocks = [cipher[i*16:(i+1)*16] for i in range(len(cipher)/16)]
        key = self._expand()
        round_keys = [key[i*16:(i+1)*16] for i in range(len(key)/16)]
        plain = array('B')
        last = self.init_vector
        for state in blocks:
            curr = state

            if self.mode == self.MODE_CFB:
                # CFB decryption requires *en*crypting the last cipher block
                # (starting with the init_vector) and then xoring with the
                # current cipher block
                state = self._encrypt(last, round_keys)
                state = self._xor(state, curr)
            else:
                state = self._decrypt(state, round_keys)

            if self.mode == self.MODE_CBC:
                # CBC decryption requires XORing with the last cipher block
                # (starting with the init_vector) after each decryption
                state = self._xor(state, last)
            last = curr

            plain.extend(state)
        return plain.tostring()
