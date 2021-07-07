#!/usr/bin/env python
import os
from collections import defaultdict, OrderedDict
from typing import Dict

from Crypto.Cipher import AES

from cryptopals_9 import pkcs7_pad
from cryptopals_10 import BLOCK_SIZE, cbc_encrypt, xor


class Client(object):
    """Dummy front-end. Makes requests to API on behalf of user.
    """
    
    def __init__(self, K, IV, account: int):
        self.K = K
        self.IV = IV

        self.account = account

    def request(self, amount: int, receiver: int) -> bytes:
        """Transfer mock funds from one account to another. Returns whether the
        transaction was successful.
        """
        msg = bytes(f'from=#{self.account}&to=#{receiver}&amount=#{amount}'.encode('UTF-8'))
        return msg + self.IV + self.generate_mac(msg)

    def request_v2(self, transactions: Dict[int, int]) -> bytes:
        """Transfer mock funds from account to others. Dictionary is a set of
        transactions.
        """
        tx_list = bytearray()
        for receiver, amount in transactions.items():
            assert isinstance(receiver, int), 'Reciever ID must be an int'
            assert isinstance(amount, int), 'Amount must be an int'

            if tx_list:
                tx_list += b';'
            tx_list += bytes(f'{receiver}:{amount}'.encode('UTF-8'))

        msg = bytes(f'from=#{self.account}&tx_list=#'.encode('UTF-8')) + tx_list
        return msg + self.generate_mac(msg)

    def generate_mac(self, msg: bytes) -> bytes:
        """Returns the MAC of a given message.
        """
        return cbc_encrypt(msg, key=self.K, iv=self.IV)[-BLOCK_SIZE:]


class API(object):
    """Dummy backend. Recieves and processes user requests.
    """

    def __init__(self):
        self.K = os.urandom(BLOCK_SIZE)
        self.IV = os.urandom(BLOCK_SIZE)
        self.reset()

    def reset(self):
        """Reset all account values.
        """
        self.accounts = defaultdict(int)

    @staticmethod
    def get_fields(msg: bytes) -> Dict[str, str]:
        """Breaks a parameter string of the format:

        <key>=#<value>(&<key>=#<value>)*
        """
        fields = {}
        for f in msg.decode('utf-8').split('&'):
            k, v = f.split('=', 2)
            assert v[0] == '#', 'First character of value should be a \#'

            fields[k] = v[1:]

        return fields

    def process(self, request: bytes) -> bool:
        """Processes a request. Returns a boolean representing whether the
        message was valid and successfully processed. Each request looks like:

            message || IV || MAC
        """
        assert len(request) > BLOCK_SIZE * 2, 'Request must be at least two blocks long'

        MSG = request[:-BLOCK_SIZE*2]
        IV = request[-BLOCK_SIZE*2:-BLOCK_SIZE]
        MAC = request[-BLOCK_SIZE:]

        expected_mac = cbc_encrypt(MSG, key=self.K, iv=IV)[-BLOCK_SIZE:]
        if MAC != expected_mac:
            return False

        fields = self.get_fields(MSG)
        amount = int(fields['amount'])
        sender = int(fields['from'])
        receiver = int(fields['to'])

        # NOTE: I don't do _any_ checking to see whether or not an account has
        #       funds. Who cares about realism?
        self.accounts[sender] -= amount
        self.accounts[receiver] += amount

        return True
    
    def process_v2(self, request: bytes) -> bool:
        """Processes a request v2, which doesn't have the IV baked into it:

            message || MAC
        """
        assert len(request) > BLOCK_SIZE, 'Request must be at least a block long'

        MSG = request[:-BLOCK_SIZE]
        MAC = request[-BLOCK_SIZE:]

        fields = self.get_fields(MSG)
        sender = int(fields['from'])

        for tx in fields['tx_list'].split(';'):
            receiver, amount = map(int, tx.split(':'))  # Brittle

            self.accounts[sender] -= amount
            self.accounts[receiver] += amount

        return True


if __name__ == '__main__':
    print('Challenge #49 - CBC-MAC Message Forgery')

    NORMIE_ID = 1234
    ATTACKER_ID = 4567

    api = API() 
    client = Client(api.K, api.IV, NORMIE_ID)

    # Verify a basic, valid request is successfully parsed and the accounts are
    # updated appropriately
    amount = 10
    receiver = 4567

    request = client.request(amount, receiver)
    assert api.process(request) 
    assert api.accounts[NORMIE_ID] == -amount
    assert api.accounts[receiver] == amount
    api.reset()

    # Now, as an attacker, generate a valid message with both sender and
    # receiver set to his account ID
    attacker_client = Client(api.K, api.IV, ATTACKER_ID)
    request = attacker_client.request(1000000, ATTACKER_ID)

    # NOTE: I've picked the attacker's account ID and the victim's account ID
    #       to be the same length (4), but perhaps as long as the attacker's ID
    #       is longer, the field could be padded with '&&&..' as needed

    # the first block looks like:
    # 
    #     from=#4567&to=#45
    #
    desired_fb = b'from=#1234&to=#4'

    msg = request[:-BLOCK_SIZE*2]
    iv = request[-BLOCK_SIZE*2:-BLOCK_SIZE]
    mac = request[-BLOCK_SIZE:]

    fb = request[:BLOCK_SIZE]
    xored_fb = xor(fb, iv)

    modified_iv = xor(desired_fb, xored_fb)

    # XOR'ing our new IV and our desired first block should produce exactly the
    # same first block cipher input as XOR'ing the original first block of
    # plaintext and IV
    assert xor(modified_iv, desired_fb) == xored_fb, 'XOR of hacked IV and desired plaintext doesn\'t match original XOR'

    # Slice together the modified request
    request = desired_fb + msg[BLOCK_SIZE:] + modified_iv + mac
    assert api.process(request), 'Hacked request wasn\'t processed successfully'
    api.reset()

    # PART 2: Fixed IVs

    # Given a valid, intercepted transaction
    valid_request = client.request_v2({444: 1000})
    valid_msg = valid_request[:-BLOCK_SIZE]
    valid_mac = valid_request[-BLOCK_SIZE:]
    assert api.process_v2(valid_request)
    api.reset()

    # 1. Create a normal message that is block-aligned (doesn't require any
    #    padding).

    # from=#4567&tx_list=#12345:123455
    txns = OrderedDict({12345: 123455})
    base_request = attacker_client.request_v2(txns)
    base_msg = base_request[:-BLOCK_SIZE]
    base_mac = base_request[-BLOCK_SIZE:]
    assert len(base_msg) % BLOCK_SIZE == 0

    # Given our desired block, modify the block by:
    # 1. XOR with our base mac, essentially zeroing that MAC out when the
    #    MAC for the longer message is computed
    # 2. XOR with the original valid MAC, knowing that that will be what is
    #    fed in in the real, server-side MAC calculation
    #
    # Append this to our original message, and then sign it to get a valid MAC
    # that we can append to the original, valid message along with the desired
    # block
    amount = 1000000
    desired_block = bytes(f';4567:{amount}'.encode())
    hacked_block = xor(xor(pkcs7_pad(desired_block), base_mac), valid_mac)
    hacked_mac = attacker_client.generate_mac(base_msg + hacked_block)
    
    hacked_request = valid_msg + desired_block + hacked_mac
    assert api.process_v2(hacked_request)
    assert api.accounts[ATTACKER_ID] == amount, "Attacker's account should have the amount credited"
