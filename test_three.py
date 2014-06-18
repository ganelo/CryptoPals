#!/usr/bin/python
from three import *

def test_17():
    plain = decrypt_cbc_side_channel()
    assert(unpad(plain) in strs)

def test_18():
    canonical_crypt = b64decode("L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ==")
    canonical_plain = "Yo, VIP Let's kick it Ice, Ice, baby Ice, Ice, baby "
    assert(crypt_aes_ctr("YELLOW SUBMARINE", 0, canonical_crypt) == canonical_plain)

    plain = "Matasano Crypto Pals"
    assert(crypt_aes_ctr("GOLDEN SUBMARINE", 0,
                         crypt_aes_ctr("GOLDEN SUBMARINE", 0, plain))
               == plain)


locs = dict(locals())
funcs = sorted(locs.keys())
for func in funcs:
    if func.startswith("test"):
        print func
        locs[func]()
