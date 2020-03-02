#!/usr/bin/env python3
"""
Test sponge and Keccak implementations.

Copyright (c), Felix Fontein, 2020

This file is BSD licensed under the Simplified BSD License
(see https://opensource.org/licenses/BSD-2-Clause).
"""

import hashlib
import itertools

import pytest

from . import keccak
from . import padding
# from . import sponge
from . import sponge_crypto


MESSAGES = [
    b'',
    b'1234',
    b'1234567890ABCDEF0123456789abcdef',
    b'Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do ' +
    b'eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ' +
    b'ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut ' +
    b'aliquip ex ea commodo consequat.',
]


@pytest.mark.parametrize("msg", [msg for msg in MESSAGES
                                 if len(msg) < 1088 // 8 - 1])
def test_keccak_f(msg):
    """Test Keccak-f."""
    f = keccak.KeccakF(6)
    S = f.new_state()
    S.from_bytes(padding.add_0110star1_padding(msg, 1088 // 8))
    f(S)
    assert S.to_bytes()[:32] == hashlib.sha3_256(msg).digest()


@pytest.mark.parametrize("msg", MESSAGES)
def test_sha_3_256(msg):
    """Test sponge hash (SHA-3-256 config)."""
    f = keccak.KeccakF(6)
    h = sponge_crypto.SpongeHash(f, 1088 // 8, padding.add_0110star1_padding)
    h.final_absorb(msg)
    assert h.squeeze(32) == hashlib.sha3_256(msg).digest()


HEADERS = [
    b'',
    b'public header',
]


KEYS = [
    b'',
    b'hunter2',
]


@pytest.mark.parametrize("key, header, data",
                         itertools.product(KEYS, HEADERS, MESSAGES))
def test_sponge_aead(key, header, data):
    """Test sponge AEAD cipher."""
    f = keccak.KeccakF(6)
    c = sponge_crypto.SpongeAEAD(f, 1088 // 8, 256 // 8, 256 // 8,
                                 padding.add_10star1_padding)
    enc_data, tag = c.encrypt_and_tag(key, header, data)
    dec_data = c.decrypt_and_authenticate(key, header, enc_data, tag)
    assert dec_data == data
