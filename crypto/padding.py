"""
Provides various padding functions.

WARNING: These implementations are for educational purposes.
         DO NOT use them for real-world applications!

Copyright (c), Felix Fontein, 2020

This file is BSD licensed under the Simplified BSD License
(see https://opensource.org/licenses/BSD-2-Clause).
"""


def _cutoff_little(data, bitlength=None):
    """Remove superfluous bits.

    This method assumes little endian encoding: the first bit
    following a byte is the 0th bit (LSB) of the next byte.

    Return bytestring, bytearray and number of remaining bits
    in last element of bytearray. If the number of remaining bits
    is 0, the bytearray can be empty.
    """
    if bitlength is not None:
        s = (bitlength + 7) // 8
        assert s <= len(data)
        if s < len(data):
            data = data[:s]
        r = bitlength & 7  # equivalent to bitlength % 8
        if r > 0:
            # Mask out the other bits
            b = bytearray([data[s - 1] & ((1 << r) - 1)])
            data = data[:-1]
            return data, b, 8 - r
    return data, bytearray(), 0


def _add_bit_little(data, appendum, remaining_bits, is_set):
    """Add set or unset bit to tuple (data, appendum, remaining_bits).

    This method assumes little endian encoding: the first bit
    following a byte is the 0th bit (LSB) of the next byte.

    Returns another such tuple with the bit appended to appendum.
    """
    if remaining_bits > 0:
        if is_set:
            appendum[-1] |= (1 << (8 - remaining_bits))
        remaining_bits -= 1
    else:
        appendum += b'\x01' if is_set else b'\x00'
        remaining_bits = 7
    return data, appendum, remaining_bits


def _cutoff_big(data, bitlength=None):
    """Remove superfluous bits.

    This method assumes big endian encoding: the first bit
    following a byte is the 7th bit (MSB) of the next byte.

    Return bytestring, bytearray and number of remaining bits
    in last element of bytearray. If the number of remaining bits
    is 0, the bytearray can be empty.
    """
    if bitlength is not None:
        s = (bitlength + 7) // 8
        assert s <= len(data)
        if s < len(data):
            data = data[:s]
        r = bitlength & 7  # equivalent to bitlength % 8
        if r > 0:
            # Mask out the other bits
            b = bytearray([data[s - 1] & (((1 << r) - 1) << (8 - r))])
            data = data[:-1]
            return data, b, 8 - r
    return data, bytearray(), 0


def _add_bit_big(data, appendum, remaining_bits, is_set):
    """Add set or unset bit to tuple (data, appendum, remaining_bits).

    This method assumes big endian encoding: the first bit
    following a byte is the 7th bit (MSB) of the next byte.

    Returns another such tuple with the bit appended to appendum.
    """
    if remaining_bits > 0:
        if is_set:
            appendum[-1] |= (1 << (remaining_bits - 1))
        remaining_bits -= 1
    else:
        appendum += b'\x80' if is_set else b'\x00'
        remaining_bits = 7
    return data, appendum, remaining_bits


def find_last_1(v):
    """Given an integer, finds the number of the highest set bit.

    The absolute value of the integer is considered.

    Returns -1 if the integer is 0, and 0 if the integer is 1.
    If the return value is i > 0, the condition
        (1 << i) <= abs(v) < (1 << (i + 1))
    is satisfied.
    """
    if v == 0:
        return -1
    return v.bit_length() - 1


def find_first_1(v):
    """Given an integer, finds the number of the lowest set bit.

    The absolute value of the integer is considered.

    Returns -1 if the integer is 0, and 0 if the integer is 1.
    """
    if v == 0:
        return -1
    i = 0
    while v & 1 == 0:
        v >>= 1
        i += 1
    return i


def add_10star_padding(data, blocksize, bitlength=None):
    """Add 10* padding to the given bytestring ``data``.

    Uses the blocksize ``blocksize`` for the padding.
    If ``bitlength`` is given, only the first ``bitlength`` bits
    of ``data`` will be considered.
    """
    data, appendum, rem_bits = _cutoff_little(data, bitlength)
    data, appendum, rem_bits = _add_bit_little(data, appendum, rem_bits, True)
    extra_bytes = (len(data) + len(appendum)) % blocksize
    if extra_bytes > 0:
        appendum += b'\x00' * (blocksize - extra_bytes)
        rem_bits = 8
    return data + appendum


def remove_10star_padding(data, blocksize=None):
    """Remove 10* padding from the given bytestring ``data``.

    Returns a pair ``(original_data, bitlength)``, where
    ``bitlength`` is the number of bits returned in ``original_data``.
    Other bits are set to 0, and the minimal number of bytes is used
    for ``original_data`` that is needed to represent the result.

    If the blocksize is provided, some sanity checks will be done
    to make sure that the original string was correctly padded.
    """
    original_data = data
    i = len(data)
    if i == 0 or (blocksize is not None and i % blocksize > 0):
        raise ValueError('Data does not satisfy 10* padding')
    while i > 0 and data[i - 1] == 0:
        i -= 1
    if i == 0:
        raise ValueError('Data does not satisfy 10* padding')
    b = find_last_1(data[i - 1])
    if b == 0:
        i -= 1
        b = 8
        data = data[:i]
    else:
        data = data[:i - 1] + bytes([data[i - 1] & ((1 << b) - 1)])
    bits = (i - 1) * 8 + b
    if blocksize is not None:
        # Validate that the minimal number of zeros was added
        min_bytes = (bits + 1 + 7) // 8
        if min_bytes + blocksize - 1 < len(original_data):
            raise ValueError('Data does not satisfy 10* padding')
    return data, bits


def add_10star1_padding(data, blocksize, bitlength=None):
    """Add 10*1 padding to the given bytestring ``data``.

    Uses the blocksize ``blocksize`` for the padding.
    If ``bitlength`` is given, only the first ``bitlength`` bits
    of ``data`` will be considered.
    """
    data, appendum, rem_bits = _cutoff_little(data, bitlength)
    data, appendum, rem_bits = _add_bit_little(data, appendum, rem_bits, True)
    extra_bytes = (len(data) + len(appendum)) % blocksize
    if extra_bytes > 0:
        appendum += b'\x00' * (blocksize - extra_bytes)
        appendum[-1] |= 0x80
    elif rem_bits > 0:
        appendum[-1] |= 0x80
    else:
        appendum += b'\x00' * (blocksize - 1) + b'\x80'
    return data + appendum


def remove_10star1_padding(data, blocksize=None):
    """Remove 10*1 padding from the given bytestring ``data``.

    Returns a pair ``(original_data, bitlength)``, where
    ``bitlength`` is the number of bits returned in ``original_data``.
    Other bits are set to 0, and the minimal number of bytes is used
    for ``original_data`` that is needed to represent the result.

    If the blocksize is provided, some sanity checks will be done
    to make sure that the original string was correctly padded.
    """
    original_data = data
    i = len(data)
    if i == 0 or (blocksize is not None and i % blocksize > 0):
        raise ValueError('Data does not satisfy 10*1 padding')
    if data[-1] & 0x80 == 0:
        raise ValueError('Data does not satisfy 10*1 padding')
    if data[-1] == 0x80:
        i -= 1
        mask = 0xff
    else:
        mask = 0x7f
    while i > 0 and data[i - 1] == 0:
        i -= 1
    if i == 0:
        raise ValueError('Data does not satisfy 10*1 padding')
    b = find_last_1(data[i - 1] & mask)
    if b == 0:
        i -= 1
        b = 8
        data = data[:i]
    else:
        data = data[:i - 1] + bytes([data[i - 1] & ((1 << b) - 1)])
    bits = (i - 1) * 8 + b
    if blocksize is not None:
        # Validate that the minimal number of zeros was added
        min_bytes = (bits + 2 + 7) // 8
        if min_bytes + blocksize - 1 < len(original_data):
            raise ValueError('Data does not satisfy 10*1 padding')
    return data, bits


def add_0110star1_padding(data, blocksize, bitlength=None):
    """Add 0110*1 padding to the given bytestring ``data``.

    Uses the blocksize ``blocksize`` for the padding.
    If ``bitlength`` is given, only the first ``bitlength`` bits
    of ``data`` will be considered.
    """
    data, appendum, rem_bits = _cutoff_little(data, bitlength)
    data, appendum, rem_bits = _add_bit_little(data, appendum, rem_bits, False)
    data, appendum, rem_bits = _add_bit_little(data, appendum, rem_bits, True)
    data += appendum
    return add_10star1_padding(data, blocksize, len(data) * 8 - rem_bits)


def remove_0110star1_padding(data, blocksize=None):
    """Remove 0110*1 padding from the given bytestring ``data``.

    Returns a pair ``(original_data, bitlength)``, where
    ``bitlength`` is the number of bits returned in ``original_data``.
    Other bits are set to 0, and the minimal number of bytes is used
    for ``original_data`` that is needed to represent the result.

    If the blocksize is provided, some sanity checks will be done
    to make sure that the original string was correctly padded.
    """
    original_data = data
    data, bits = remove_10star1_padding(data, blocksize)
    if bits < 2:
        raise ValueError('Data does not satisfy 0110*1 padding')
    b = bits & 7  # equivalent to bits % 8
    if b == 0:
        b = 8
    if data[-1] & (1 << (b - 1)) == 0:
        raise ValueError('Data does not satisfy 0110*1 padding')
    if b <= 2:
        if b == 2:
            mask = 1
            idx = -1
        else:  # b == 1
            mask = 1 << 7
            idx = -2
        if data[idx] & mask != 0:
            raise ValueError('Data does not satisfy 0110*1 padding')
        data = data[:-1]
    else:  # b > 2
        data = data[:-1] + bytes([data[-1] & ((1 << (b - 2)) - 1)])
    bits -= 2
    if blocksize is not None:
        # Validate that the minimal number of zeros was added
        min_bytes = (bits + 5 + 7) // 8
        if min_bytes + blocksize - 1 < len(original_data):
            raise ValueError('Data does not satisfy 0110*1 padding')
    return data, bits


def add_sha2_padding(data, blocksize, bitlength=None):
    """Add SHA-2 padding to the given bytestring ``data``.

    Uses the blocksize ``blocksize`` for the padding.
    If ``bitlength`` is given, only the first ``bitlength`` bits
    of ``data`` will be considered.
    """
    data, appendum, rem_bits = _cutoff_big(data, bitlength)
    if bitlength is None:
        bitlength = len(data) * 8
    data, appendum, rem_bits = _add_bit_big(data, appendum, rem_bits, True)
    extra_bytes = (len(data) + len(appendum) + 8) % blocksize
    if extra_bytes > 0:
        appendum += b'\x00' * (blocksize - extra_bytes)
    appendum += bitlength.to_bytes(8, byteorder='big')
    return data + appendum


def remove_sha2_padding(data, blocksize=None):
    """Remove SHA2 padding from the given bytestring ``data``.

    Returns a pair ``(original_data, bitlength)``, where
    ``bitlength`` is the number of bits returned in ``original_data``.
    Other bits are set to 0, and the minimal number of bytes is used
    for ``original_data`` that is needed to represent the result.

    If the blocksize is provided, some sanity checks will be done
    to make sure that the original string was correctly padded.
    """
    i = len(data)
    if i < 9 or (blocksize is not None and i % blocksize > 0):
        raise ValueError('Data does not satisfy SHA-2 padding')
    i -= 8
    length = int.from_bytes(data[i:], byteorder='big')
    while i > 0 and data[i - 1] == 0:
        i -= 1
    if i == 0:
        raise ValueError('Data does not satisfy SHA-2 padding')
    b = find_first_1(data[i - 1])
    if b == 7:
        i -= 1
        b = 0
        result = data[:i]
    else:
        b += 1
        last_byte = data[i - 1] & (((1 << (8 - b)) - 1) << b)
        result = data[:i - 1] + bytes([last_byte])
    length_ = (i - 1) * 8 + (8 - b)
    if length_ != length:
        raise ValueError('Data does not satisfy SHA-2 padding')
    if blocksize is not None:
        # Validate that the minimal number of zeros was added
        min_bytes = (length + 8) // 8 + 8
        if min_bytes + blocksize - 1 < len(data):
            raise ValueError('Data does not satisfy SHA-2 padding')
    return result, length
