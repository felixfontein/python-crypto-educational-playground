#!/usr/bin/env python3
"""
Test SHA2 implementation.

Copyright (c), Felix Fontein, 2020

This file is BSD licensed under the Simplified BSD License
(see https://opensource.org/licenses/BSD-2-Clause).
"""

import hashlib
import itertools

import pytest

from . import sha3


MESSAGES = [
    b'',
    b'1234',
    b'1234567890ABCDEF0123456789abcdef',
    b'Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do ' +
    b'eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ' +
    b'ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut ' +
    b'aliquip ex ea commodo consequat.',
]


OUTPUT_SIZES = [
    0,
    1,
    2,
    4,
    15,
    16,
    17,
    31,
    32,
    33,
    63,
    64,
    65,
    1000,
]


@pytest.mark.parametrize("msg", MESSAGES)
def test_sha_3_224(msg):
    """Test SHA-3-224 hash."""
    assert sha3.sha_3_224(msg) == hashlib.sha3_224(msg).digest()


@pytest.mark.parametrize("msg", MESSAGES)
def test_sha_3_256(msg):
    """Test SHA-3-256 hash."""
    assert sha3.sha_3_256(msg) == hashlib.sha3_256(msg).digest()


@pytest.mark.parametrize("msg", MESSAGES)
def test_sha_3_384(msg):
    """Test SHA-3-384 hash."""
    assert sha3.sha_3_384(msg) == hashlib.sha3_384(msg).digest()


@pytest.mark.parametrize("msg", MESSAGES)
def test_sha_3_512(msg):
    """Test SHA-3-512 hash."""
    assert sha3.sha_3_512(msg) == hashlib.sha3_512(msg).digest()


@pytest.mark.parametrize("msg, output_size",
                         itertools.product(MESSAGES, OUTPUT_SIZES))
def test_shake128(msg, output_size):
    """Test SHAKE-128 XOF."""
    v = sha3.shake128(msg, output_size)
    assert v == hashlib.shake_128(msg).digest(output_size)


@pytest.mark.parametrize("msg, output_size",
                         itertools.product(MESSAGES, OUTPUT_SIZES))
def test_shake256(msg, output_size):
    """Test SHAKE-256 XOF."""
    v = sha3.shake256(msg, output_size)
    assert v == hashlib.shake_256(msg).digest(output_size)
