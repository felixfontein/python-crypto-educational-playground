#!/usr/bin/env python3
"""
A simple sponge function based on AES-256.

Copyright (c), Felix Fontein, 2020

This file is BSD licensed under the Simplified BSD License
(see https://opensource.org/licenses/BSD-2-Clause).
"""

from crypto import aes
from crypto import padding
from crypto import sponge
from crypto import sponge_crypto


class State(sponge.State):
    """
    The state consists of 16 bytes.
    """

    def __init__(self):
        self.data = b'\x00' * 16

    def from_bytes(self, value):
        assert len(value) <= 16
        if len(value) < 16:
            value = value + b'\x00' * (16 - len(value))
        self.data = bytes([a ^ b for a, b in zip(self.data, value)])

    def to_bytes(self):
        return self.data

    def clone(self):
        result = State()
        result.data = self.data
        return result


AES_KEY = b'Dies ist ein nicht geheimer Key!'


class F(sponge.F):
    def new_state(self):
        return State()

    def __call__(self, state):
        state.data = aes.aes_encrypt(state.data, AES_KEY)


# Hash

for text in [
    'Test 1234',
    'Test 1235',
    'Test 12345',
]:
    c = sponge_crypto.SpongeHash(F(), 10, padding.add_10star1_padding)
    c.final_absorb(text.encode('utf-8'))
    h = c.squeeze(16)
    print('Hash("{0}"){2} == {1}'.format(
        text, h.hex(':'), ' ' * max(0, 20 - len(text))))


# AEAD

c = sponge_crypto.SpongeAEAD(F(), 10, 8, 16, padding.add_10star1_padding)

key = 'Test 1234'.encode('utf-8')

for text, oeffentlich in [
    ('Das Passwort ist 1234', 'Geheimer Text für Nicole'),
    ('Das Passwort ist 1235', 'Geheimer Text für Nicole'),
    ('Das Passwort ist 12345', 'Geheimer Text für Nicole'),
]:
    verschluesselt, tag = c.encrypt_and_tag(key,
                                            oeffentlich.encode('utf-8'),
                                            text.encode('utf-8'))
    entschluesselt = c.decrypt_and_authenticate(key,
                                                oeffentlich.encode('utf-8'),
                                                verschluesselt, tag)
    assert entschluesselt == text.encode('utf-8')
    print('"{0}"/"{1}" ==>'.format(text, oeffentlich))
    print('  TAG {0} / ENC {1}'.format(tag.hex(':'), verschluesselt.hex(':')))
