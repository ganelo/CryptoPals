#!/usr/bin/python
from base64 import b64encode, b64decode
from array import array
from two import *

# 17
k = None
strs = ["MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=",
        "MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic=",
        "MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw==",
        "MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg==",
        "MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl",
        "MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA==",
        "MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw==",
        "MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8=",
        "MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g=",
        "MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93"]
def create_cookie():
    global k
    if not k:
        k = random_key()
    plain = pad(random.choice(strs), 16)
    return (encrypt_aes_128_cbc(plain, k), "\x00"*16)

def validate_cookie(cipher, iv):
    aes = AES(k, AES.MODE_CBC, init_vector=iv)
    plain = aes.decrypt(cipher)
    try:
        validate_padding(plain)
        return True
    except ValueError:
        return False

def decrypt_cbc_side_channel():
    cipher, iv = create_cookie()
    # To learn the bytes in the first block of the cipher, we will need to mofidy
    # the iv for XORing, so treat the iv + cipher as a single entity for XORing
    cipher = iv + cipher
    plain = ""
    l = len(plain)
    while l < len(cipher) - len(iv):
        # Don't check 0 b/c for e.g. the very first (last) byte, 0 will always be valid
        # as long as the original was valid - this will give us the incorrect impression
        # that the first (last) byte is actually 00, throwing off our whole calculation
        for i in xrange(1, 256):
            byte = ("%02x" % i)
            # xor in the previous block (or iv) to effect change in desired block
            byte_pattern = ("00"*(len(cipher) - 17 - l) +
                            byte +
                            # take known bytes and xor them to get desired values
                            fixed_xor(plain.decode("hex")[:l/16*-16+l].encode("hex"),
                                      ("%02x" % ((l % 16) + 1)) * (l % 16)) +
                            "00"*(16 + l/16*16))
            # Since we XOR the known bytes w/ our desired values (e.g. 030303)
            # and those bytes will be XORed with the bytes in the correct location
            # (one block forward) on decrypt, we guarantee that we wind up with the
            # desired values because (n^03)^n = 03 for all n

            # xor resulting pattern with cipher to get change in plaintext
            new_cipher = fixed_xor(cipher.encode("hex"),
                                   byte_pattern).decode("hex")
            # when modifying the first block of the cipher, we change the iv,
            # so peel it back off for passing into the validator
            new_iv, new_cipher = new_cipher[:16], new_cipher[16:]
            # strip blocks off the back as we discover them
            new_cipher = new_cipher[:l/16*-16+len(new_cipher)]
            if validate_cookie(new_cipher, new_iv):
                plain = "%02x" % (((l % 16) + 1)^i) + plain
                if l == 0:
                    # This was guaranteed to be a padding byte,
                    # so we know that the next <byte> bytes are
                    # identical
                    l += int(plain, 16)
                    plain = plain * int(plain, 16)
                else:
                    l += 1
                break
    return plain.decode("hex")

# 18
import struct
def crypt_aes_ctr(key, nonce, txt):
    crypted_txt = ""
    nonce = struct.pack("<Q", nonce)
    blocks = 0
    while len(txt)/16.0 > blocks:
        ctr = struct.pack("<Q", blocks)
        aes = AES(key, mode=AES.MODE_ECB)
        keystream = aes.encrypt(nonce+ctr)
        block = txt[blocks*16:(blocks+1)*16]
        crypted_txt += fixed_xor(block.encode("hex"),
                                 keystream[:len(block)].encode("hex"))
        blocks += 1
    return crypted_txt.decode("hex")

# 19
def crypt_aes_ctr_fixed_nonce(key, txt):
    return crypt_aes_ctr(key, 0, txt)

plains = ["SSBoYXZlIG1ldCB0aGVtIGF0IGNsb3NlIG9mIGRheQ==",
          "Q29taW5nIHdpdGggdml2aWQgZmFjZXM=",
          "RnJvbSBjb3VudGVyIG9yIGRlc2sgYW1vbmcgZ3JleQ==",
          "RWlnaHRlZW50aC1jZW50dXJ5IGhvdXNlcy4=",
          "SSBoYXZlIHBhc3NlZCB3aXRoIGEgbm9kIG9mIHRoZSBoZWFk",
          "T3IgcG9saXRlIG1lYW5pbmdsZXNzIHdvcmRzLA==",
          "T3IgaGF2ZSBsaW5nZXJlZCBhd2hpbGUgYW5kIHNhaWQ=",
          "UG9saXRlIG1lYW5pbmdsZXNzIHdvcmRzLA==",
          "QW5kIHRob3VnaHQgYmVmb3JlIEkgaGFkIGRvbmU=",
          "T2YgYSBtb2NraW5nIHRhbGUgb3IgYSBnaWJl",
          "VG8gcGxlYXNlIGEgY29tcGFuaW9u",
          "QXJvdW5kIHRoZSBmaXJlIGF0IHRoZSBjbHViLA==",
          "QmVpbmcgY2VydGFpbiB0aGF0IHRoZXkgYW5kIEk=",
          "QnV0IGxpdmVkIHdoZXJlIG1vdGxleSBpcyB3b3JuOg==",
          "QWxsIGNoYW5nZWQsIGNoYW5nZWQgdXR0ZXJseTo=",
          "QSB0ZXJyaWJsZSBiZWF1dHkgaXMgYm9ybi4=",
          "VGhhdCB3b21hbidzIGRheXMgd2VyZSBzcGVudA==",
          "SW4gaWdub3JhbnQgZ29vZCB3aWxsLA==",
          "SGVyIG5pZ2h0cyBpbiBhcmd1bWVudA==",
          "VW50aWwgaGVyIHZvaWNlIGdyZXcgc2hyaWxsLg==",
          "V2hhdCB2b2ljZSBtb3JlIHN3ZWV0IHRoYW4gaGVycw==",
          "V2hlbiB5b3VuZyBhbmQgYmVhdXRpZnVsLA==",
          "U2hlIHJvZGUgdG8gaGFycmllcnM/",
          "VGhpcyBtYW4gaGFkIGtlcHQgYSBzY2hvb2w=",
          "QW5kIHJvZGUgb3VyIHdpbmdlZCBob3JzZS4=",
          "VGhpcyBvdGhlciBoaXMgaGVscGVyIGFuZCBmcmllbmQ=",
          "V2FzIGNvbWluZyBpbnRvIGhpcyBmb3JjZTs=",
          "SGUgbWlnaHQgaGF2ZSB3b24gZmFtZSBpbiB0aGUgZW5kLA==",
          "U28gc2Vuc2l0aXZlIGhpcyBuYXR1cmUgc2VlbWVkLA==",
          "U28gZGFyaW5nIGFuZCBzd2VldCBoaXMgdGhvdWdodC4=",
          "VGhpcyBvdGhlciBtYW4gSSBoYWQgZHJlYW1lZA==",
          "QSBkcnVua2VuLCB2YWluLWdsb3Jpb3VzIGxvdXQu",
          "SGUgaGFkIGRvbmUgbW9zdCBiaXR0ZXIgd3Jvbmc=",
          "VG8gc29tZSB3aG8gYXJlIG5lYXIgbXkgaGVhcnQs",
          "WWV0IEkgbnVtYmVyIGhpbSBpbiB0aGUgc29uZzs=",
          "SGUsIHRvbywgaGFzIHJlc2lnbmVkIGhpcyBwYXJ0",
          "SW4gdGhlIGNhc3VhbCBjb21lZHk7",
          "SGUsIHRvbywgaGFzIGJlZW4gY2hhbmdlZCBpbiBoaXMgdHVybiw=",
          "VHJhbnNmb3JtZWQgdXR0ZXJseTo=",
          "QSB0ZXJyaWJsZSBiZWF1dHkgaXMgYm9ybi4="]

key = random_key()
crypts = [crypt_aes_ctr_fixed_nonce(key, b64decode(p)) for p in plains]

# 20
def decrypt_fixed_nonce_ctr(ciphers):
#    keysize = min(map(len, ciphers))
    keysize = max(map(len, ciphers))
    cipher = array('B',"".join(cipher+"\x00"*(keysize-len(cipher)) for cipher in ciphers))

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

    plain = str(hex_to_bytes(repeating_key_xor(cipher.tostring().encode("hex"), key)))

    return [plain[i:i+keysize] for i in range(0, len(cipher), keysize)]

with open("three_twenty_data.txt") as f:
    plains = map(b64decode, f.readlines())

ciphers = [crypt_aes_ctr_fixed_nonce(key, p) for p in plains]

print "\n".join(decrypt_fixed_nonce_ctr(ciphers))
