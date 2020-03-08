#!/usr/bin/env python3
"""
A simple sponge function.

Copyright (c), Felix Fontein, 2020

This file is BSD licensed under the Simplified BSD License
(see https://opensource.org/licenses/BSD-2-Clause).
"""

from crypto import aes
from crypto import padding
from crypto import utils


def new_state():
    '''Create new state.'''
    return [0] * 16


def state_to_bytes(state):
    '''Convert state to byte string.'''
    return b''.join([v.to_bytes(1, byteorder='little') for v in state])


def add_bytes_to_state(state, value):
    '''Add byte string to state.'''
    assert len(value) <= len(state)
    if len(value) < len(state):
        value = value + b'\x00' * (len(state) - len(value))
    for i in range(len(state)):
        state[i] ^= int.from_bytes(value[i:i + 1], byteorder='little')


# Hexadecimal fractional digits of π
# https://www.pi2e.ch/blog/wp-content/uploads/2017/03/pi_hex_1k.txt
ROUND_KEYS = [
    (0x24, 0x3f, 0x6a, 0x88, 0x85, 0xa3, 0x08, 0xd3,
     0x13, 0x19, 0x8a, 0x2e, 0x03, 0x70, 0x73, 0x44,),
    (0xa4, 0x09, 0x38, 0x22, 0x29, 0x9f, 0x31, 0xd0,
     0x08, 0x2e, 0xfa, 0x98, 0xec, 0x4e, 0x6c, 0x89,),
    (0x45, 0x28, 0x21, 0xe6, 0x38, 0xd0, 0x13, 0x77,
     0xbe, 0x54, 0x66, 0xcf, 0x34, 0xe9, 0x0c, 0x6c,),
    (0xc0, 0xac, 0x29, 0xb7, 0xc9, 0x7c, 0x50, 0xdd,
     0x3f, 0x84, 0xd5, 0xb5, 0xb5, 0x47, 0x09, 0x17,),
    (0x92, 0x16, 0xd5, 0xd9, 0x89, 0x79, 0xfb, 0x1b,
     0xd1, 0x31, 0x0b, 0xa6, 0x98, 0xdf, 0xb5, 0xac,),
    (0x2f, 0xfd, 0x72, 0xdb, 0xd0, 0x1a, 0xdf, 0xb7,
     0xb8, 0xe1, 0xaf, 0xed, 0x6a, 0x26, 0x7e, 0x96,),
    (0xba, 0x7c, 0x90, 0x45, 0xf1, 0x2c, 0x7f, 0x99,
     0x24, 0xa1, 0x99, 0x47, 0xb3, 0x91, 0x6c, 0xf7,),
    (0x08, 0x01, 0xf2, 0xe2, 0x85, 0x8e, 0xfc, 0x16,
     0x63, 0x69, 0x20, 0xd8, 0x71, 0x57, 0x4e, 0x69,),
    (0xa4, 0x58, 0xfe, 0xa3, 0xf4, 0x93, 0x3d, 0x7e,
     0x0d, 0x95, 0x74, 0x8f, 0x72, 0x8e, 0xb6, 0x58,),
    (0x71, 0x8b, 0xcd, 0x58, 0x82, 0x15, 0x4a, 0xee,
     0x7b, 0x54, 0xa4, 0x1d, 0xc2, 0x5a, 0x59, 0xb5,),
    (0x9c, 0x30, 0xd5, 0x39, 0x2a, 0xf2, 0x60, 0x13,
     0xc5, 0xd1, 0xb0, 0x23, 0x28, 0x60, 0x85, 0xf0,),
]


def substitute(v):
    '''Apply AES S-box to value.'''
    return aes.AES_S_BOX[v]


def xor(values):
    '''Return XOR of all values.'''
    result = values[0]
    for v in values[1:]:
        result ^= v
    return result


def permute(state):
    '''Permute state.'''
    # Einfach nur eine Drehung bewirkt zu wenig: keine Diffusion!
    return [xor(values) for values in zip(
        utils.rotate_value_list(state, 31),
        utils.rotate_value_list(state, 56),
        utils.rotate_value_list(state, 111),
        utils.rotate_value_list(state, 1),
    )]


def f(state):
    for i in range(11):
        # Substitute values
        for j in range(len(state)):
            state[j] = substitute(state[j])
        # Permute values
        state = permute(state)
        # Add round key
        rk = ROUND_KEYS[i % 11]
        for j in range(len(rk)):
            state[j] = (state[j] + rk[j]) % 256
    return state


# Hash

def compute_hash(input):
    '''Compute sponge hash with above sponge f function.'''
    # Create new state
    state = new_state()
    # Pad input
    input = padding.add_10star1_padding(input, 10)
    # Absorb phase:
    for i in range(0, len(input), 10):
        add_bytes_to_state(state, input[i:i + 10])
        state = f(state)
    # Squeeze phase:
    first = state_to_bytes(state)[:10]
    state = f(state)
    second = state_to_bytes(state)[:6]
    # Return result
    return first + second


for text in [
    'Test 1234',
    'Test 1235',
    'Test 12345',
]:
    h = compute_hash(text.encode('utf-8'))
    print('Hash("{0}"){2} == {1}'.format(
        text, h.hex(':'), ' ' * max(0, 20 - len(text))))
