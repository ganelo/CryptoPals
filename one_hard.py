#!/usr/bin/python
from base64 import b64encode, b64decode

# HELPER FUNCTIONS
def hex_to_bytes(h):
    return bytearray.fromhex(h)

def bytes_to_hex(b):
    return str(b).encode("hex")

# 1.1
def hex_to_b64(h):
    return b64encode(h.decode("hex"))

def b64_to_hex(b):
    return b64decode(b).encode("hex")

# 1.2
def fixed_xor(a, b):
    a = hex_to_bytes(a)
    b = hex_to_bytes(b)
    c = bytearray()
    for index, byte in enumerate(a):
        c.append(byte^b[index])
    return str(c).encode("hex")

# 1.3
import string, sys
from collections import Counter
def score(msg):
    # Attempt to rule out non-printable characters
    if msg != filter(lambda c: c in string.printable, msg):
        return 0

    orig = msg

    # Normalize message to get good frequency analysis
    msg = filter(lambda c: c in string.ascii_letters, msg).lower()

    counts = Counter(msg)
    freqs = {c: counts[c]/float(len(msg)) for c in counts}

    # From Robert Lewand's 'Cryptological Mathematics'
    expected = {'a': 0.08167, 'b': 0.01492, 'c': 0.02782, 'd': 0.04253,
                'e': 0.12702, 'f': 0.02228, 'g': 0.02015, 'h': 0.06094,
                'i': 0.06966, 'j': 0.00153, 'k': 0.00772, 'l': 0.04025,
                'm': 0.02406, 'n': 0.06749, 'o': 0.07507, 'p': 0.01929,
                'q': 0.00095, 'r': 0.05987, 's': 0.06327, 't': 0.09056,
                'u': 0.02758, 'v': 0.00978, 'w': 0.02360, 'x': 0.00150,
                'y': 0.01974, 'z': 0.00074}
    
    # The longer the message, the closer the frequencies should be
    # So multiply frequency differences by the length of the message
    # Also, the more non-letter characters that had to be removed
    # from the message, the more suspect the score, so multiply
    # by the difference in length as well
    diff = sum(abs(expected[c] - freqs[c]) for c in msg)
    len_diff = len([i for i in orig if i not in (string.ascii_letters+" ")])
    # Use len(orig) instead of len(msg) so messages with extremely few
    # ascii characters don't get an advantage
    diff *= len(orig)*(len_diff or 1)

    # Extremely unlikely, but ultimately possible that the freqs match exactly
    if not diff:
        return sys.maxint

    return 1./diff

def get_single_character_xor_key(cipher):
    plain = []
    scores = []
    for i in range(256):
        key = ("%02x" % i) * (len(cipher)/2)
        plaintext = str(hex_to_bytes(fixed_xor(cipher, key)))
        plain.append(plaintext)
        scores.append(score(plaintext))

    m = max(scores)
    return scores.index(m)

def decrypt_single_character_xor(cipher):
    key = get_single_character_xor_key(cipher)
    return str(hex_to_bytes(fixed_xor(cipher, ("%02x" % key)*(len(cipher)/2))))

# 1.4
def detect_single_character_xor(seq):
    plain = []
    scores = []
    for cipher in seq:
        plaintext = decrypt_single_character_xor(cipher)
        plain.append(plaintext)
        scores.append(score(plaintext))

    m = max(scores)
    i = scores.index(m)
    return plain[i]

# 1.5
def repeating_key_xor(a, b):
    key = b * ((len(a)/len(b)) + 1)
    key = key[:len(a)]
    return fixed_xor(a, key)

# 1.6
def hamming_distance(a, b):
    return bin(int(fixed_xor(a, b), 16)).count("1")

def decrypt_repeating_key_xor(cipher_hex):
    cipher = hex_to_bytes(cipher_hex)
    keys = {}
    for keysz in range(2, 41):
        # To maximize chance of correct keysize, average hamming distance over
        # all blocks instead of just the first 2 or 4 or even the first n
        sim = [hamming_distance(bytes_to_hex(cipher[i*keysz:(i+1)*keysz]),
                                bytes_to_hex(cipher[(i+1)*keysz:(i+2)*keysz]))
                   for i in range(len(cipher)/keysz-2)]
        # Divide by number of blocks (to get average) and by keysize (for norming)
        sim = sum(sim)/(len(cipher)/keysz-2)/keysz
        keys[keysz] = sim

    # Get keysize with minimum average normalized hamming distance
    keysize = min(keys.keys(), key=keys.__getitem__)
    
    # Since this is a repeating key, we need to attempt a single-character key
    # decryption on every <keysize> bytes (for keysize of 2, plain text of ABCD
    # is encrypted as [A^key[0], B^key[1], C^key[0], D^key[1]]; so to go the
    # other way you can just try to find key[0] by decrypting [A^key[0], C^key[0]]
    # using existing single-character xor decryption)
    blocks = [cipher[i:i+keysize]
                  for i in range(0, len(cipher), keysize)]
    transpose = map(lambda seq: ''.join("%02x" % i for i in seq if i),
                    map(None, *blocks))

    key = ""
    for i, block in enumerate(transpose):
        key += "%02x" % get_single_character_xor_key(block)

    return str(hex_to_bytes(repeating_key_xor(cipher_hex, key)))

# 1.7
from otpyrc import AES
def decrypt_aes_128_ecb(cipher, key):
    aes = AES(key)
    return aes.decrypt(cipher)

# 1.8
def detect_aes_128_ecb(seq):
    # Judging from the hint ("the same 16 byte plaintext block will always
    # produce the same 16 byte ciphertext"), the approach to take is to
    # try to find duplicate blocks of cipher text, in the hope that there
    # are duplicated blocks of plaintext.  If there aren't duplicate blocks
    # of plaintext, there may not be a good way of detecting if the ciphertext
    # was encrypted using ECB.  We also must assume that the same key was used
    # to encrypt every block of plaintext; otherwise, the blocks of ciphertext
    # would not repeat even if the blocks of plaintext did.  Also, unlike with
    # 1.4, brute-forcing the key is not practical because our search space is
    # 2^128 instead of 2^8; so we must suffice with detecting which cipher
    # was encrypted using ECB instead of additionally managing to decrypt it.
    repeats = []
    for cipher in seq:
        cipher = hex_to_bytes(cipher)
        blocks = [cipher[i:i+16] for i in range(0, len(cipher), 16)]
        dupes = Counter(map(bytes_to_hex,blocks))
        # Only care when a block appears more than once
        repeats.append(sum(dupes.values())-len(dupes.keys()))

    m = max(repeats)
    i = repeats.index(m)
    return seq[i]

