#!/usr/bin/python
from one import *

def test_1_1():
    h = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"
    b = "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t"
    b_prime = hex_to_b64(h)
    h_prime = b64_to_hex(b)
    assert(h == h_prime)
    assert(b == b_prime)

def test_1_2():
    a = "1c0111001f010100061a024b53535009181c"
    b = "686974207468652062756c6c277320657965"
    res_exp = "746865206b696420646f6e277420706c6179"
    res = fixed_xor(a, b)
    assert(res == res_exp)

def test_1_3():
    c = '1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736'
    plain = decrypt_single_character_xor(c)
    assert(plain == "Cooking MC's like a pound of bacon")

def test_1_4():
    with open("one_four_data.txt", "r") as f:
        seq = map(string.strip, f.readlines())
    plain = detect_single_character_xor(seq)
    assert(plain == "Now that the party is jumping\n")

def test_1_5():
    plain = ("Burning 'em, if you ain't quick and nimble\n" +
             "I go crazy when I hear a cymbal")
    cipher = repeating_key_xor(plain.encode("hex"), "ICE".encode("hex"))
    expected = ("0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a" +
                "26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027" +
                "630c692b20283165286326302e27282f")
    assert(cipher == expected)

def test_hamming_distance():
    assert(hamming_distance("this is a test".encode("hex"),
                            "wokka wokka!!!".encode("hex")) == 37)

def test_1_6():
    with open("one_six_data.txt", "r") as f:
        b64 = f.read()
    cipher = b64_to_hex(b64)
    with open("one_common_data.txt", "r") as f:
        expected = f.read()
    assert(decrypt_repeating_key_xor(cipher) == expected)

def test_1_7():
    with open("one_seven_data.txt", "r") as f:
        cipher = b64_to_hex(f.read().strip()).decode("hex")
    key = "YELLOW SUBMARINE"
    plain = decrypt_aes_128_ecb(cipher, key)

    # Discard padding: n bytes on end of plaintext w/ value n
    i = -1
    while plain[i] == plain[-1]:
        i -= 1
    # last check failed, so re-increment i
    i += 1
    padding = bytearray.fromhex(plain[i:].encode("hex"))
    assert(len(padding) == padding[-1])
    plain = plain[:i]

    with open("one_common_data.txt", "r") as f:
        expected = f.read()
    assert(plain == expected)

def test_1_8():
    with open("one_eight_data.txt", "r") as f:
        seq = [line.strip() for line in f.readlines() if line]
    # As it turns out, of the ciphertexts in the seq, only one has
    # any repeats, and it has one block present 4 times, which is
    # pretty indicative.
    print detect_aes_128_ecb(seq)

locs = dict(locals())
funcs = sorted(locs.keys())
for func in funcs:
    if func.startswith("test"):
        print func
        locs[func]()
