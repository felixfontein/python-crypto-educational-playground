#!/usr/bin/env python3
"""
Test sponge and Keccak implementations.

Copyright (c), Felix Fontein, 2020

This file is BSD licensed under the Simplified BSD License
(see https://opensource.org/licenses/BSD-2-Clause).
"""

import itertools
import os

import pytest

from . import aes
from . import cipher
from . import ciphermodes
from . import padding

try:
    from cryptography.hazmat.primitives.ciphers import (
        Cipher, modes, algorithms
    )
    from cryptography.hazmat.backends import default_backend
    HAS_CRYPTOGRAPHY = True
except ImportError:
    HAS_CRYPTOGRAPHY = False


MESSAGES = [
    b'',
    b'1234',
    b'1234567890ABCDEF0123456789abcdef',
    b'Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do ' +
    b'eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ' +
    b'ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut ' +
    b'aliquip ex ea commodo consequat.',
]


KEYS = [
    os.urandom(32),
    os.urandom(32),
]


IVS = [
    os.urandom(16),
    os.urandom(16),
]


def compare_ciphers(c1, c2, plaintext):
    """Compare output of two ciphers."""
    # Encrypt/decrypt with cryptography.io cipher
    encryptor = c1.encryptor()
    enc_io = encryptor.update(plaintext)
    enc_io += encryptor.finalize()
    decryptor = c1.decryptor()
    dec_io = decryptor.update(enc_io)
    dec_io += decryptor.finalize()
    assert plaintext == dec_io
    # print(enc_io.hex(':'))

    # Encrypt/decrypt with our cipher
    enc_our = c2.encryptor()(plaintext)
    dec_our = c2.decryptor()(enc_our)
    assert plaintext == dec_our
    # print(enc_our.hex(':'))

    # Compare
    assert enc_io == enc_our


if HAS_CRYPTOGRAPHY:
    @pytest.mark.parametrize("key, data",
                             itertools.product(KEYS, MESSAGES))
    def test_aes_ecb(key, data):
        """Test AES-ECB."""
        compare_ciphers(
            Cipher(algorithms.AES(key), modes.ECB(), default_backend()),
            cipher.Cipher.from_block_cipher(aes.AES256(),
                                            ciphermodes.ECB(key)),
            padding.add_10star_padding(data, 16))

    @pytest.mark.parametrize("key, iv, data",
                             itertools.product(KEYS, IVS, MESSAGES))
    def test_aes_ctr(key, iv, data):
        """Test AES-CTR."""
        compare_ciphers(
            Cipher(algorithms.AES(key), modes.CTR(iv), default_backend()),
            cipher.Cipher.from_block_cipher(aes.AES256(),
                                            ciphermodes.CTR(key, iv)),
            data)

    @pytest.mark.parametrize("key, iv, data",
                             itertools.product(KEYS, IVS, MESSAGES))
    def test_aes_cbc(key, iv, data):
        """Test AES-CBC."""
        compare_ciphers(
            Cipher(algorithms.AES(key), modes.CBC(iv), default_backend()),
            cipher.Cipher.from_block_cipher(aes.AES256(),
                                            ciphermodes.CBC(key, iv)),
            padding.add_10star_padding(data, 16))
