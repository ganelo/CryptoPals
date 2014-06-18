#!/usr/bin/python
from two import *

def test_9():
    plain = "YELLOW SUBMARINE"
    assert(pad(plain, 16) == plain)
    assert(pad(plain, 3) == plain+"\x02\x02")
    assert(pad(plain, 20) == plain+"\x04\x04\x04\x04")

def test_10():
    plain = "plaintext string"
    key = "YELLOW SUBMARINE"
    assert(decrypt_aes_128_ecb(encrypt_aes_128_ecb(plain, key), key) == plain)
    assert(decrypt_aes_128_cbc(encrypt_aes_128_cbc(plain, key), key) == plain)

def test_11():
    ecbs = 0
    for _ in xrange(1000):
        mode = detect_oracle_block_cipher_mode(encryption_oracle("A"*1000))
        if mode == "ECB":
            ecbs += 1
    assert(600 > ecbs > 400)

def test_12():
    expected = "Rollin' in my 5.0\nWith my rag-top down so my hair can blow\nThe girlies on standby waving just to say hi\nDid you stop? No, I just drove by\n"
    assert(decrypt_unknown_string() == expected)

def test_13():
    assert(create_admin()["role"] == "admin")

def test_14():
    expected = "Rollin' in my 5.0\nWith my rag-top down so my hair can blow\nThe girlies on standby waving just to say hi\nDid you stop? No, I just drove by\n"
    assert(decrypt_unknown_string_with_prepend() == expected)

def test_15():
    assert(validate_padding("ICE ICE BABY\x04\x04\x04\x04") == "ICE ICE BABY")
    try:
        validate_padding("ICE ICE BABY\x05\x05\x05\x05")
    except ValueError:
        pass
    else:
        raise AssertionError
    try:
        validate_padding("ICE ICE BABY\x01\x02\x03\x04")
    except ValueError:
        pass
    else:
        raise AssertionError

def test_16():
    assert(bit_flip_cbc())

locs = dict(locals())
funcs = sorted(locs.keys())
for func in funcs:
    if func.startswith("test"):
        print func
        locs[func]()
