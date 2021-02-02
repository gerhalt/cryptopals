#!/usr/bin/env python

import argparse
import os
import sys
import time
from argparse import ArgumentParser
from http import HTTPStatus

import requests
from flask import Flask, jsonify, request

from cryptopals_28 import sha1
from cryptopals_31 import insecure_compare

app = Flask(__name__)

SECRET_KEY = os.urandom(24)


@app.route('/test')
def test():
    f = request.args.get('file')
    if f is None:
        return jsonify("'file' parameter is missing"), HTTPStatus.BAD_REQUEST

    signature = request.args.get('signature')
    if signature is None:
        return jsonify("'signature' parameter is missing"), HTTPStatus.BAD_REQUEST

    f = bytes(f.encode('utf-8'))

    try:
        signature = int(signature, 16).to_bytes(20, 'big')
    except OverflowError:
        return jsonify("Signature is too long, should be 20 bytes"), HTTPStatus.BAD_REQUEST
    except ValueError:
        return jsonify("Signature must be composed only of hexadecimal digits"), HTTPStatus.BAD_REQUEST

    hmac = sha1(SECRET_KEY + f)
    print(f'Expected HMAC is {hmac.hex()}')

    if insecure_compare(hmac, signature, sleep=0.005):
        return '', HTTPStatus.NO_CONTENT
    else:
        return jsonify("Signature does not match"), HTTPStatus.INTERNAL_SERVER_ERROR


def better_timing_attack():
    """Makes requests to a running server, attempting to use our artificial
    timing leak to determine whether is correct.
    """
    s = requests.session()

    trials = 5

    signature = bytearray(20)
    for idx in range(0, len(signature)):

        best_time = None
        for b in range(0, 0xFF):
            signature[idx] = b

            total_duration = 0
            for trial in range(0, trials):
                start = time.time()
                try:
                    resp = s.get(
                        'http://localhost:9000/test',
                        params={
                            'file': 'some file contents',
                            'signature': signature.hex()
                        })
                except requests.exceptions.ConnectionError:
                    sys.stderr.write('Unable to connect to server\n')
                    sys.stderr.flush()
                    sys.exit(1)
                total_duration += time.time() - start

            avg = total_duration / trials
            #print(f'Test of byte {b:02x} over {trials} trials took, on average, {avg:.2} seconds')

            if not best_time:
                best_time = avg
                last_b = b
            elif avg > best_time:
                best_time = avg
                last_b = b

        signature[idx] = last_b

    # Verify the signature we've found is correct
    resp = s.get(
        'http://localhost:9000/test',
        params={
            'file': 'some file contents',
            'signature': signature.hex()
        })

    assert resp.status_code == 204, 'Guessed hash should return a 204'


if __name__ == '__main__':
    print('Challenge #32 - Break HMAC-SHA1 with a slightly less artificial timing leak')

    parser = ArgumentParser(
        description='Launches either a client or server for challenge #31')
    parser.add_argument(
        'role', choices=('client', 'server'),
        help='Which role to launch')

    args = parser.parse_args()

    if args.role == 'client':
        better_timing_attack()
    elif args.role == 'server':
        app.run(host='localhost', port=9000, debug=True)
