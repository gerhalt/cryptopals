#!/usr/bin/env python

import os
import sys
import time
from argparse import ArgumentParser
from http import HTTPStatus

import requests
from flask import Flask, jsonify, request

from cryptopals_29 import sha1

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
    print(f'Expected digest is: {hmac.hex()}')

    if insecure_compare(hmac, signature):
        return '', HTTPStatus.NO_CONTENT
    else:
        return jsonify("Signature does not match"), HTTPStatus.INTERNAL_SERVER_ERROR


def compare(hmac: bytes, signature: bytes) -> bool:
    """Compare the SHA1 HMAC of the contents of a file appended to our server
    secret.
    """
    return hmac == signature


def insecure_compare(hmac: bytes, signature: bytes, sleep: float = 0.05) -> bool:
    """Compare the SHA1 HMAC of the contents of a file appended to our server
    secret. Compare each byte one by one, and exit early if a byte doesn't
    match. Lastly, waits 50ms after each byte position is compared.
    """
    if len(hmac) != len(signature):
        return jsonify("Signature is not 160 bits"), HTTPStatus.BAD_REQUEST

    for a, b in zip(hmac, signature):
        if a != b:
            return False

        time.sleep(sleep)

    return True


def artificial_timing_attack():
    """Makes requests to a running server, attempting to use our artificial
    timing leak to determine whether is correct.
    """
    s = requests.session()

    signature = bytearray(20)
    for idx in range(0, len(signature)):
        last_time = None

        for b in range(0, 0xFF):
            signature[idx] = b

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
            end = time.time()

            duration = end - start
            print(f'Test of byte {b:02x} took {duration:.2} seconds')

            if not last_time:
                last_time = duration
                last_b = b
            elif duration > last_time + 0.045:
                last_b = b
                break

        signature[idx] = b

    # Verify the signature we've found is correct
    resp = s.get(
        'http://localhost:9000/test',
        params={
            'file': 'some file contents',
            'signature': signature.hex()
        })

    assert resp.status_code == 204, 'Guessed hash should return a 204'


if __name__ == '__main__':
    print('Challenge #31 - Implement and break HMAC-SHA1 with an artificial timing leak')

    parser = ArgumentParser(
        description='Launches either a client or server for challenge #31')
    parser.add_argument(
        'role', choices=('client', 'server'),
        help='Which role to launch')

    args = parser.parse_args()

    if args.role == 'client':
        artificial_timing_attack()
    elif args.role == 'server':
        app.run(host='localhost', port=9000, debug=True)
