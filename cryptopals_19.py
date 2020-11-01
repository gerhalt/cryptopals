#!/usr/bin/env python

from base64 import b64decode
from os import urandom

from cryptopals_3 import score_english
from cryptopals_10 import xor
from cryptopals_18 import aes_ctr


INPUTS = (b64decode(s) for s in (
    b'SSBoYXZlIG1ldCB0aGVtIGF0IGNsb3NlIG9mIGRheQ==',
    b'Q29taW5nIHdpdGggdml2aWQgZmFjZXM=',
    b'RnJvbSBjb3VudGVyIG9yIGRlc2sgYW1vbmcgZ3JleQ==',
    b'RWlnaHRlZW50aC1jZW50dXJ5IGhvdXNlcy4=',
    b'SSBoYXZlIHBhc3NlZCB3aXRoIGEgbm9kIG9mIHRoZSBoZWFk',
    b'T3IgcG9saXRlIG1lYW5pbmdsZXNzIHdvcmRzLA==',
    b'T3IgaGF2ZSBsaW5nZXJlZCBhd2hpbGUgYW5kIHNhaWQ=',
    b'UG9saXRlIG1lYW5pbmdsZXNzIHdvcmRzLA==',
    b'QW5kIHRob3VnaHQgYmVmb3JlIEkgaGFkIGRvbmU=',
    b'T2YgYSBtb2NraW5nIHRhbGUgb3IgYSBnaWJl',
    b'VG8gcGxlYXNlIGEgY29tcGFuaW9u',
    b'QXJvdW5kIHRoZSBmaXJlIGF0IHRoZSBjbHViLA==',
    b'QmVpbmcgY2VydGFpbiB0aGF0IHRoZXkgYW5kIEk=',
    b'QnV0IGxpdmVkIHdoZXJlIG1vdGxleSBpcyB3b3JuOg==',
    b'QWxsIGNoYW5nZWQsIGNoYW5nZWQgdXR0ZXJseTo=',
    b'QSB0ZXJyaWJsZSBiZWF1dHkgaXMgYm9ybi4=',
    b'VGhhdCB3b21hbidzIGRheXMgd2VyZSBzcGVudA==',
    b'SW4gaWdub3JhbnQgZ29vZCB3aWxsLA==',
    b'SGVyIG5pZ2h0cyBpbiBhcmd1bWVudA==',
    b'VW50aWwgaGVyIHZvaWNlIGdyZXcgc2hyaWxsLg==',
    b'V2hhdCB2b2ljZSBtb3JlIHN3ZWV0IHRoYW4gaGVycw==',
    b'V2hlbiB5b3VuZyBhbmQgYmVhdXRpZnVsLA==',
    b'U2hlIHJvZGUgdG8gaGFycmllcnM/',
    b'VGhpcyBtYW4gaGFkIGtlcHQgYSBzY2hvb2w=',
    b'QW5kIHJvZGUgb3VyIHdpbmdlZCBob3JzZS4=',
    b'VGhpcyBvdGhlciBoaXMgaGVscGVyIGFuZCBmcmllbmQ=',
    b'V2FzIGNvbWluZyBpbnRvIGhpcyBmb3JjZTs=',
    b'SGUgbWlnaHQgaGF2ZSB3b24gZmFtZSBpbiB0aGUgZW5kLA==',
    b'U28gc2Vuc2l0aXZlIGhpcyBuYXR1cmUgc2VlbWVkLA==',
    b'U28gZGFyaW5nIGFuZCBzd2VldCBoaXMgdGhvdWdodC4=',
    b'VGhpcyBvdGhlciBtYW4gSSBoYWQgZHJlYW1lZA==',
    b'QSBkcnVua2VuLCB2YWluLWdsb3Jpb3VzIGxvdXQu',
    b'SGUgaGFkIGRvbmUgbW9zdCBiaXR0ZXIgd3Jvbmc=',
    b'VG8gc29tZSB3aG8gYXJlIG5lYXIgbXkgaGVhcnQs',
    b'WWV0IEkgbnVtYmVyIGhpbSBpbiB0aGUgc29uZzs=',
    b'SGUsIHRvbywgaGFzIHJlc2lnbmVkIGhpcyBwYXJ0',
    b'SW4gdGhlIGNhc3VhbCBjb21lZHk7',
    b'SGUsIHRvbywgaGFzIGJlZW4gY2hhbmdlZCBpbiBoaXMgdHVybiw=',
    b'VHJhbnNmb3JtZWQgdXR0ZXJseTo=',
    b'QSB0ZXJyaWJsZSBiZWF1dHkgaXMgYm9ybi4='
))


if __name__ == '__main__':
    print('Challenge #19 - Break fixed-nonce CTR mode using substitutions')

    nonce = 0
    key = urandom(16)

    ciphertexts = set()
    for plaintext in INPUTS:
        ciphertexts.add(aes_ctr(key, nonce, plaintext))

    # Iterate through each byte index in our ciphertexts, looking for a
    # keystream byte that results in the most english-looking set of bytes in
    # that position
    guessed_keystream = []
    idx = 0
    unfinished_ciphertexts = list(ciphertexts)
    while True:
        current_bytes = []
        for ct in list(unfinished_ciphertexts):
            # Remove any ciphertexts that are too short to work with for this
            # and any future determinations
            if idx >= len(ct):
                unfinished_ciphertexts.remove(ct)
                continue

            current_bytes.append(ct[idx])

        if not current_bytes:
            break

        best_score = None
        best_byte = None
        for test_byte in range(0, 256):
            test_score = score_english(bytes([i ^ test_byte for i in current_bytes]))
            if best_score is None or test_score > best_score:
                best_score = test_score
                best_byte = test_byte

        guessed_keystream.append(best_byte)

        idx += 1

    print(f'Guessed Keystream: {bytes(guessed_keystream)}')
    for ct in ciphertexts:
        print(xor(guessed_keystream, ct))
