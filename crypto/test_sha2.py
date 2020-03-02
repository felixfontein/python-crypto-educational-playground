#!/usr/bin/env python3
"""
Test SHA2 implementation.

Copyright (c), Felix Fontein, 2020

This file is BSD licensed under the Simplified BSD License
(see https://opensource.org/licenses/BSD-2-Clause).
"""

import hashlib

import pytest

from . import sha2


MESSAGES = [
    b'',
    b'1234',
    b'1234567890ABCDEF0123456789abcdef',
    b'Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do ' +
    b'eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ' +
    b'ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut ' +
    b'aliquip ex ea commodo consequat.',
]


@pytest.mark.parametrize("msg", MESSAGES)
def test_sha_2_256(msg):
    """Test SHA-2-256 hash."""
    assert sha2.sha_2_256(msg) == hashlib.sha256(msg).digest()
