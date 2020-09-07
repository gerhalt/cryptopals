#!/usr/bin/env python

import base64

from Crypto.Cipher import AES


if __name__ == '__main__':
    print('Challenge #7 - AES in ECB Mode')

    key = b'YELLOW SUBMARINE'
    with open('data/1.7.txt', 'rb') as f:
        text = base64.b64decode(f.read())

        cipher = AES.new(key, AES.MODE_ECB)  # IV is ignored
        print(cipher.decrypt(text))
