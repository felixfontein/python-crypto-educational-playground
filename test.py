#!/usr/bin/env python3
"""
Does some basic sanity testing.

Copyright (c), Felix Fontein, 2020

This file is BSD licensed under the Simplified BSD License
(see https://opensource.org/licenses/BSD-2-Clause).
"""

from crypto import keccak
from crypto import padding
from crypto import sponge_crypto


f = keccak.KeccakF(6)
c = sponge_crypto.SpongeAEAD(f, 1088 // 8, 256 // 8, 256 // 8,
                             padding.add_10star1_padding)
key = b'hunter2'
header = b'public header'
data = b'secret data!'
encrypted_data, tag = c.encrypt_and_tag(key, header, data)
decrypted_data = c.decrypt_and_authenticate(key, header, encrypted_data, tag)
assert decrypted_data == data
