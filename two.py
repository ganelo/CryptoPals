#!/usr/bin/python
from base64 import b64encode, b64decode
from array import array
from one import *

# 9
def pad(plain, size):
    if not len(plain) % size:
        diff = size
    else:
        diff = size - (len(plain) % size)
    return "%s%s" % (plain, ("%02x" % diff).decode("hex")*diff)

def unpad(plain):
    try:
        num = int(plain[-1].encode("hex"), 16)
    except ValueError:
        return plain
    if plain[-1*num:] == ("%02x" % num).decode("hex")*num:
        return plain[:-1*num]
    return plain

# 10
from crpyto import AES
def encrypt_aes_128_ecb(plain, key):
    aes = AES(key, AES.MODE_ECB)
    return aes.encrypt(plain)

def encrypt_aes_128_cbc(plain, key, iv="\x00"*16):
    plain = array('B', plain)
    blocks = [plain[i*16:(i+1)*16] for i in range(len(plain)/16)]
    last = array('B', iv)
    cipher = array('B')
    for block in blocks:
        state = array('B',fixed_xor(last.tostring().encode("hex"),
                                    block.tostring().encode("hex")).decode("hex"))
        last = array('B', encrypt_aes_128_ecb(state.tostring(), key))
        cipher.extend(last)
    return cipher.tostring()

def decrypt_aes_128_cbc(cipher, key, iv="\x00"*16):
    cipher = array('B', cipher)
    blocks = [cipher[i*16:(i+1)*16] for i in range(len(cipher)/16)]
    last = array('B', iv)
    plain = array('B')
    for block in blocks:
        state = array('B', decrypt_aes_128_ecb(block.tostring(), key))
        state = array('B', fixed_xor(last.tostring().encode("hex"),
                                     state.tostring().encode("hex")).decode("hex"))
        plain.extend(state)
        last = block
    return plain.tostring()

# 11
import random
def random_key(num=16):
    return array('B',[random.randint(0, 255) for _ in range(num)])

def encryption_oracle(plaintext):
    key = random_key().tostring()
    plaintext = pad(random_key(random.randint(5,10)).tostring() +
                    plaintext +
                    random_key(random.randint(5,10)).tostring(),
                    16)
    if random.randint(0,1):
        iv = random_key().tostring()
        return encrypt_aes_128_cbc(plaintext, key, iv)
    return encrypt_aes_128_ecb(plaintext, key)

def detect_oracle_block_cipher_mode(ciphertext):
    cipher = array('B', ciphertext)
    blocks = [cipher[i:i+16] for i in range(0, len(cipher), 16)]
    dupes = Counter(map(bytes_to_hex, blocks))
    repeats = sum(dupes.values())-len(dupes.keys())
    if repeats:
        return "ECB"
    return "CBC"

# 12
UNKNOWN_KEY = random_key()
def encrypt_aes_128_ecb_unknown_key(plaintext):
    return encrypt_aes_128_ecb(pad(plaintext, 16), UNKNOWN_KEY)

def padded_encrypt_aes_128_ecb_unknown_key(plaintext):
    padding = ("Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkga"+
               "GFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdX"+
               "N0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK")
    return encrypt_aes_128_ecb_unknown_key(pad(plaintext +
                                               b64decode(padding),
                                               16))

def decrypt_unknown_string():
    pad_enc_unk = padded_encrypt_aes_128_ecb_unknown_key
    enc_unk = encrypt_aes_128_ecb_unknown_key

    # discover block size
    num_bytes = 0
    blocksize = 0
    last_size = len(pad_enc_unk("A"*num_bytes))
    while not blocksize:
        cipher = pad_enc_unk("A"*num_bytes)
        size = len(cipher)
        blocksize = size - last_size
        last_size = size
        num_bytes += 1
    
    # ECB or CBC?
    ecb = detect_oracle_block_cipher_mode(pad_enc_unk("A"*1000)) == "ECB"
    assert(ecb)
    
    # Decrypt
    unknown = ""
    # Proceed byte-by-byte until encrypting what we have without padding is
    # identical to encrypting nothing with padding
    while enc_unk(unknown) != pad_enc_unk(""):
        # blocksize-0-1, blocksize-1-1, ..., blocksize-(blocksize-2)-1,
        # blocksize-0-1, ...
        num_bytes = blocksize - (len(unknown) % blocksize) - 1
        short = "A"*num_bytes
        mapping = {}
        # First encrypt A*(blocksize-1) + guess and try to match actual output
        # of cipher; as bytes are discovered, replace As with bytes of string
        # (e.g. A*(blocksize - 5)XXXX + guess) and try to match actual output
        # of cipher
        for i in xrange(256):
            guess = ("%02x" % i).decode("hex")
            cipher = pad_enc_unk(short + unknown + guess)
            mapping[cipher[:len(short+unknown+guess)]] = guess

        cipher = pad_enc_unk(short)
        unknown += mapping[cipher[:len(short+unknown+guess)]]

    unknown = unpad(unknown)
    return unknown

# 13
def kv_dec(s):
    return dict(map(lambda pair: pair.split("="), s.split("&")))

def kv_enc(d):
    keys = ["email", "uid", "role"]
    return "&".join("=".join((k, d[k])) for k in keys)

profiles = {}
def profile_for(email):
    email = email.replace("&", "").replace("=", "")
    if not email in profiles:
        profiles[email] = kv_dec("email=%s&uid=%s&role=user" %
                                 (email, len(profiles.keys())))
    return kv_enc(profiles[email])

RANDOM_AES_KEY = random_key()
def encrypted_profile_for(email):
    return encrypt_aes_128_ecb(pad(profile_for(email),16), RANDOM_AES_KEY)

def profile(cipher):
    return kv_dec(unpad(decrypt_aes_128_ecb(cipher, RANDOM_AES_KEY)))

def create_admin():
    # Get a block that looks like '....&role=' by manipulating the
    # length of the email address; then we can get a different block with e.g.
    # 'admin\x0b...' to drop in at the end

    # We want 'admin\x0b...' in its own block, so offset by padding the front
    # until we hit blocksize bytes
    blocksize = 16
    admin_block_plain = '0' * (blocksize - len('email=')) + pad('admin', 16)
    admin_cipher = encrypted_profile_for(admin_block_plain)
    admin_block = admin_cipher[16:32]

    # Now create an email that has a block border after 'role='
    email_var = 'email='
    uid_var = '&uid='
    role_var = '&role='
    exp_uid_len = 1
    uid = ""
    while len(uid) != exp_uid_len:
        trailer = ""
        exp_uid_len = len(uid)
        back = uid_var + "0"*exp_uid_len + role_var
        incl = blocksize - len(back)
        want = blocksize - len(email_var) + incl
        # Not necessary; would just be nice to actually have control of the
        # email account and have it pass validation
        if want > 8:
            want -= 8
            trailer = "@bar.com"
        email = "0"*want + trailer
        uid = profile(encrypted_profile_for(email))["uid"]

    # Now we know the profile exists, so we don't need to worry about the uid
    # length changing
    cipher = encrypted_profile_for(email)
    cipher = cipher[:-16] + admin_block

    return profile(cipher)

# 14
def prepended_padded_encrypt_aes_128_ecb_unknown_key(plaintext):
    pre_pad = random_key(random.randint(1, 16)).tostring()
    padding = ("Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkga"+
               "GFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdX"+
               "N0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK")
    return encrypt_aes_128_ecb_unknown_key(pad(pre_pad +
                                               plaintext +
                                               b64decode(padding),
                                               16))

def dupes_of_len(l, txt):
    if l >= len(txt) or l < 1:
        return []
    dupes = []
    times = {}
    for index in xrange(len(txt)-l):
        pattern = txt[index:index+l]
        times[pattern] = times.setdefault(pattern, -1) + 1
        if times[pattern]:
            dupes.append(pattern)
    return dupes

def just_dupes_of_len(l, txt):
    for index in xrange(0, len(txt)/l*l-l, l):
        if txt[index:index+l] != txt[:l]:
            return False
    return True
            
def decrypt_unknown_string_with_prepend():
    # Harder b/c can't (directly) control how many bytes of fixed_string
    #     are present in a given block.  Get around this by collecting all
    #     16 possible shifted versions of the fixed_string and comparing
    #     all bytes (\x00-\xff) + padding with the collected blocks.
    #     To get around unknown length of prefix, use repeating pattern
    #     with blocksize - 1 filler bytes inbetween; this guarantees at
    #     least one correctly-aligned block of output
    pre_pad_enc_unk = prepended_padded_encrypt_aes_128_ecb_unknown_key

    # To calculate block size, put in a ton of known bytes as input
    # e.g. "A"*1000.  Look for the longest range of bytes that occurs
    # (overlapped) twice in the output - this is the multi-block section
    # that corresponds to the block-aligned portion of your input
    # excluding one block.
    # Find the length of the portion of this multiblock that repeats - it
    # should be of length blocksize
    cipher = pre_pad_enc_unk("A"*1000)
    num_bytes = 1000
    while not dupes_of_len(num_bytes, cipher):
        num_bytes -= 1
        if not num_bytes:
            print "Could not calculate block size at multiblock step"
            return False
    multiblock = dupes_of_len(num_bytes, cipher)[0]
    num_bytes = 1
    while not just_dupes_of_len(num_bytes, multiblock):
        num_bytes += 1
        if num_bytes > len(multiblock)/2:
            print "Could not calculate block size at sub-multiblock step"
            return False
    blocksize = num_bytes
    assert(blocksize == 16)

    # ECB or CBC?
    ecb = detect_oracle_block_cipher_mode(cipher) == "ECB"
    assert(ecb)

    # 2 blocksize's worth of As guarantees that there is always at least
    #     one block of As - and at most 2 blocks of As
    # There are at most blocksize different arrangements of the fixed string
    #     so keep putting in the same input until we see them all (relying on
    #     the random length, random byte string at the front to shift through
    #     them all)
    ablock = multiblock[:blocksize]
    seen = set()
    while len(seen) < blocksize:
        cipher = pre_pad_enc_unk("A"*blocksize*2)
        try:
            seen.add(cipher[cipher.rindex(ablock)+blocksize:])
        except ValueError:
            # if ablock not present, then we got really unlucky;
            # the random bytes at the front mimicked some portion
            # of the block during the calculation of the multiblock,
            # so we have a different rotation of the ablock instead
            for i in xrange(blocksize):
                if ablock not in cipher:
                    ablock = ablock[1:] + ablock[0]
            if ablock not in cipher:
                print "Could not locate ablock in cipher?!"
                return False
            seen.add(cipher[cipher.rindex(ablock)+blocksize:])
    seen = list(seen)

    # Of these blocksize arrangements, we know one must have a final block
    #     that looks like '?' + '\x0f'*15.  So, attempt to find '?' by
    #     putting in combos of bytes w/ \x0f until we get a match post-enc.
    # Continue this process w/ ever reducing amounts of padding until we
    #     have a whole block of the fixed string
    # Then, always do ?XXXXXXXXXXXXXXX where XXXXXXXXXXXXXX is the 15 bytes
    #     at the front of what we've collected from the fixed_string so far
    fixed_string = ""
    rand_bytes = 0
    old = "blah"
    while fixed_string != old:
        old = fixed_string
        found = False
        for i in xrange(256):
            # By padding 15 null bytes each time, we guarantee we will eventually
            # get one blocksize-aligned block regardless of the length of the
            # random bytes at the front
            if len(fixed_string) < blocksize:
                padding = blocksize - len(fixed_string) - 1
                pattern = ((("%02x" % i).decode("hex") +
                            "%s" % fixed_string +
                            ("%02x" % padding).decode("hex")*padding +
                            "\x00" * (blocksize - 1))*blocksize +
                           "A"*blocksize*2)
            else:
                pattern = ((("%02x" % i).decode("hex") +
                            "%s" % fixed_string[:blocksize-1] +
                            "\x00" * (blocksize - 1))*blocksize +
                           "A"*blocksize*2)
            cipher = pre_pad_enc_unk(pattern)
            for index in xrange(0, len(cipher)-blocksize, blocksize):
                block = cipher[index:index+blocksize]
                if block == ablock: # went through whole pattern
                    break
                if any([block in shifted for shifted in seen]):
                    fixed_string = ("%02x" % i).decode("hex") + fixed_string
                    found = True
                    break
            if found:
                break
   
    # We're guaranteed that at this point, we have 15 bytes of A before the
    #     real text because that would be the last block with a match
    fixed_string = fixed_string[blocksize-1:]
    return fixed_string

# 15
def validate_padding(txt):
    res = unpad(txt)
    if res == txt:
        raise ValueError("Invalid padding")
    return res

# 16
RANDOM_AES_KEY = random_key()
def encrypted_data(txt):
    txt = ("comment1=cooking%20MCs;userdata=" + 
           txt.replace(";","\;").replace("=","\=") +
           ";comment2=%20like%20a%20pound%20of%20bacon")
    return encrypt_aes_128_cbc(pad(txt, 16), RANDOM_AES_KEY)

def admin_present(cipher):
    txt = validate_padding(decrypt_aes_128_cbc(cipher, RANDOM_AES_KEY))
    return ";admin=true;" in txt

# It should be pretty obvious why the block in which the bit has been flipped
#     will be completely mangled - the column and row mixing ensures that,
#     within a block, every bit affects every other bit.
# The reason that the 1-bit error propagates is that in CBC mode, the cipher
#     text is XORd with the next block's plaintext.  Since the cipher text
#     has one bit flipped, the result of the XOR will also have the bit flipped
def bit_flip_cbc():
    cipher = encrypted_data("a"*16 + # sacrificial block
                            ("%02x" % (ord(";")^32)).decode("hex") +
                            "admin" +
                            ("%02x" % (ord("=")^32)).decode("hex") +
                            "true").encode("hex")
    cipher = (cipher[:64] + # first 2 blocks are fixed
              fixed_xor(cipher[64:96], "20" + "00"*5 + "20" + "00"*9) +
              cipher[96:]).decode("hex")
    return admin_present(cipher)
