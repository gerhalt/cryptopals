#!/usr/bin/env python

from random import randint

from cryptopals_39 import modinv, RSA


if __name__ == '__main__':
    print('Challenge #40 - Implement an E=3 RSA Broadcast Attack')

    # Attacker can decrypt by:
    # 1. Capturing any 3 ciphertexts and corresponding public keys
    # 2. Using the CRT to solve for the number represented by the three
    #     ciphertexts
    # 3. Taking the cube root of the resulting number

    # Generate three public keys, and ensure they're different from each other
    # (only check n, because we know e=3)
    rsa_0 = RSA()
    rsa_1 = RSA()
    rsa_2 = RSA()
    assert len(set([rsa_0.n, rsa_1.n, rsa_2.n])) == 3
    
    # Given some random input number
    inp = randint(1, 10000)

    c_0 = rsa_0.encrypt(inp) % rsa_0.n
    c_1 = rsa_1.encrypt(inp) % rsa_1.n
    c_2 = rsa_2.encrypt(inp) % rsa_2.n

    # m_s_n (for n in 0, 1, 2) are the product of the moduli EXCEPT n_n ---
    # ie, m_s_1 is n_0 * n_2
    m_s_0 = rsa_1.n * rsa_2.n
    m_s_1 = rsa_0.n * rsa_2.n
    m_s_2 = rsa_0.n * rsa_1.n

    N_012 = rsa_0.n * rsa_1.n * rsa_2.n

    # Chinese Remainder Theorem
    result = (
        c_0 * m_s_0 * modinv(m_s_0, rsa_0.n) + 
        c_1 * m_s_1 * modinv(m_s_1, rsa_1.n) + 
        c_2 * m_s_2 * modinv(m_s_2, rsa_2.n)
    ) % N_012

    # Take the cube root, round and convert to an integer
    decrypted = int(round(result ** (1 / 3), 0))

    assert inp == decrypted
