#!/usr/bin/env python

import os
from base64 import b64decode

from Crypto.Cipher import AES

from cryptopals_8 import detect_duplicate_blocks
from cryptopals_9 import pkcs7_pad


def aes_encrypt(key: bytes, msg: bytes) -> bytes:
    """
    Encrypts the input with AES and the given key
    """
    padded_msg = pkcs7_pad(msg, 16)

    cipher = AES.new(key, AES.MODE_ECB)
    encrypted_msg = cipher.encrypt(padded_msg)

    return encrypted_msg


def aes_decrypt(key: bytes, msg: bytes) -> bytes:
    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.decrypt(msg)


class Profile(object):

    def __init__(self):
        self.attrs = list()

    def __setattr__(self, k, v):
        super().__setattr__(k, v)

        if k != 'attrs':
            self.attrs.append(k)

    def __repr__(self):
        out = []
        for attr in self.attrs:
            out.append(f'{attr}: {getattr(self, attr)}')

        return '\n'.join(out)
    
    def __str__(self):
        return '&'.join([f'{k}={getattr(self, k)}' for k in self.attrs])


def kv_parser(inp: str):
    profile = Profile()

    pairs = inp.split('&')
    for p in pairs:
        k, v = p.split('=')
        setattr(profile, k, v)

    return profile

def profile_for(email: str):
    email = email.replace('=', '')
    email = email.replace('&', '')
    
    user_id = 33332
    role = 'user'

    return kv_parser(f'email={email}&uid={user_id}&role={role}')


if __name__ == '__main__':
    print('Challenge #13 - ECB cut-and-paste')

    key = os.urandom(16)

    # Derive block size
    last_size = None
    for i in range(0, 256):
        profile = bytes(str(profile_for(' ' * i)).encode())
        profile_len = len(aes_encrypt(key, profile))
        if last_size is None:
            last_size = profile_len
        elif last_size != profile_len:
            block_size = profile_len - last_size
            break

    # Buffer to align with the end of the block
    end_align_padding = i
    print(f'Padding to align text to end is {end_align_padding}')

    print(f'Block size is {block_size} bytes')

    # Create duplicate blocks to identify where the
    # first full block we have access to begins, after the unknown prefix
    for i in range(block_size * 2, block_size * 3):
        profile = bytes(str(profile_for(' ' * i)).encode())
        dups = detect_duplicate_blocks(aes_encrypt(key, profile))
        if dups:
            break

    # Padding to align input + unknown prefix to the next block index
    initial_padding = i - block_size * 2

    # Fails if earlier duplicates exist
    first_block = min(map(min, dups.values()))

    # Create "admin" + padding input that exactly occupies one block
    profile = initial_padding * ' ' + pkcs7_pad(b'admin').decode()
    encrypted_profile = aes_encrypt(key, bytes(str(profile_for(profile)).encode()))

    admin_block = encrypted_profile[first_block:first_block+block_size]

    # Create an input that shifts the "user" portion of "role=user" into its
    # own block
    profile = (end_align_padding + len('user')) * ' '
    encrypted_profile = aes_encrypt(key, bytes(str(profile_for(profile)).encode()))

    # Now swap out the last block with our padded "admin" block
    chopped_profile = encrypted_profile[:-block_size] + admin_block
    decrypted_profile = aes_decrypt(key, chopped_profile)

    assert b'role=admin' in decrypted_profile
