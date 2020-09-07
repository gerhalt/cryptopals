#!/usr/bin/env python

from collections import defaultdict
from typing import Tuple


VOWELS = set('aeiouy')
CONSONANTS = set('bcdfghjklmnpqrstvwxz') 


def score_english(inp: str) -> float:
    """
    Accepts a string, and returns how likely it is to be valid english.
    """
    count = defaultdict(int)

    vowel_count = 0
    consonant_count = 0
    other_count = 0

    for c in inp:
        count[chr(c)] += 1

    vowel_count = sum([count[c] for c in VOWELS])
    consonant_count = sum([count[c] for c in CONSONANTS])
    other_count = sum([v for k, v in count.items() if k not in VOWELS and k not in CONSONANTS])
    if not consonant_count:
        consonant_count = 1

    score = 0

    # Heavily prefer spaces to non-alpha characters
    score += 1 - abs(0.8 - (count[' '] / other_count))

    # Alphabetical characters should make up ~90% of the text
    score += 1 - abs(0.9 - (vowel_count + consonant_count) / len(inp))
    
    return score


def byte_xor_guesser(s: str) -> Tuple[float, int, str]:
    """ Guesses the most likely key and original string the input `s` was
    derived from, assuming it was originally English text).

    Returns
    -------
        (float, int, str): The score, byte xor'd against the original string,
            and the best-guess original string
    """
    best_score = 0
    guess = None
    guess_key = None
    all_guesses = []
    for key in range(0, 256):
        test_string = bytes(map(lambda c: c ^ key, int(s, 16).to_bytes(len(s) // 2, byteorder='big')))
        score = score_english(test_string)

        if score > best_score:
            best_score = score
            guess = test_string
            guess_key = key

        all_guesses.append((score, test_string))

    # Debugging
    all_guesses.sort(key=lambda x: x[0], reverse=True)
    for s, g in all_guesses[:10]:
        pass  # print(s, g)

    return (best_score, guess_key, guess)


if __name__ == '__main__':
    print('Challenge #3 - Single-Byte XOR Cipher')

    inp = '1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736'
    score, key, original = byte_xor_guesser(inp)

    print('{:.3f} {}'.format(score, original))
