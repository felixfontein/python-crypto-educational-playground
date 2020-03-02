#!/usr/bin/env python3
"""
Test padding functions.

Copyright (c), Felix Fontein, 2020

This file is BSD licensed under the Simplified BSD License
(see https://opensource.org/licenses/BSD-2-Clause).
"""

import os

import pytest

from . import padding


def generate_input(mode, msgsize):
    """Generate input data."""
    if mode == 0:
        return bytes([0x00] * msgsize)
    if mode == 1:
        return bytes([0xff] * msgsize)
    return os.urandom(msgsize)


def cap_input(input_bytes, bitsize, little_endian):
    """Trim input so it contains exactly ``bitsize`` bits."""
    assert bitsize <= 8 * len(input_bytes)
    if bitsize < 8 * len(input_bytes):
        no_bytes = (bitsize + 7) // 8
        if little_endian:
            mask = (1 << (bitsize % 8)) - 1
        else:
            mask = ((1 << (bitsize % 8)) - 1)
            mask <<= (8 - (bitsize % 8))
        last_byte = input_bytes[no_bytes - 1] & mask
        input_bytes = input_bytes[:no_bytes - 1] + bytes([last_byte])
    return input_bytes


def create_adding_test_params():
    """Create testing parameters."""
    result = []
    for blocksize in [1, 2, 3, 4, 15, 16, 17]:
        msgsizes = set(range(0, 3))
        msgsizes.update(range(max(0, blocksize - 2), blocksize + 3))
        msgsizes.update(range(max(0, 2 * blocksize - 2), blocksize * 2 + 3))
        for msgsize in sorted(msgsizes):
            result.append((blocksize, msgsize, None, 0))
            bitsizes = list(range(max(0, msgsize * 8 - 7), msgsize * 8 + 1))
            for bitsize in bitsizes:
                for add in range(3):
                    result.append((blocksize, msgsize, bitsize, add))
    return result


def check_padding(pad, unpad, little_endian, blocksize,
                  msgsize, bitsize, add, mode):
    """Tests a padding."""
    msg_compare = generate_input(mode, msgsize)
    msg = msg_compare
    if bitsize is not None:
        msg += os.urandom(add)
        msg_compare = cap_input(msg_compare, bitsize, little_endian)
    padded_msg = pad(msg, blocksize, bitsize)
    assert len(padded_msg) > 0
    assert len(padded_msg) % blocksize == 0
    unpadded_msg, bs = unpad(padded_msg, blocksize)
    assert unpadded_msg == msg_compare
    if bitsize is not None:
        assert bitsize == bs
    else:
        assert len(msg_compare) * 8 == bs


@pytest.mark.parametrize("blocksize, msgsize, bitsize, add",
                         create_adding_test_params())
def test_10star_padding(blocksize, msgsize, bitsize, add):
    """Test 10* padding."""
    for mode in range(10):
        check_padding(padding.add_10star_padding,
                      padding.remove_10star_padding,
                      True,
                      blocksize,
                      msgsize,
                      bitsize,
                      add,
                      mode)


@pytest.mark.parametrize("blocksize, msgsize, bitsize, add",
                         create_adding_test_params())
def test_10star1_padding(blocksize, msgsize, bitsize, add):
    """Test 10*1 padding."""
    for mode in range(10):
        check_padding(padding.add_10star1_padding,
                      padding.remove_10star1_padding,
                      True,
                      blocksize,
                      msgsize,
                      bitsize,
                      add,
                      mode)


@pytest.mark.parametrize("blocksize, msgsize, bitsize, add",
                         create_adding_test_params())
def test_0110star1_padding(blocksize, msgsize, bitsize, add):
    """Test 0110*1 padding."""
    for mode in range(10):
        check_padding(padding.add_0110star1_padding,
                      padding.remove_0110star1_padding,
                      True,
                      blocksize,
                      msgsize,
                      bitsize,
                      add,
                      mode)


@pytest.mark.parametrize("blocksize, msgsize, bitsize, add",
                         create_adding_test_params())
def test_sha2_padding(blocksize, msgsize, bitsize, add):
    """Test SHA-2 padding."""
    for mode in range(10):
        check_padding(padding.add_sha2_padding,
                      padding.remove_sha2_padding,
                      False,
                      blocksize,
                      msgsize,
                      bitsize,
                      add,
                      mode)
