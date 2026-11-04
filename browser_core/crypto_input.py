"""Strict private witness of WebCrypto's copied digest input, never raw bytes."""
from __future__ import annotations

import re

MAX_INPUT_BYTES = 1024 * 1024
BOUNDARY = 'after-algorithm-normalization-before-dispatch'
PARAMETERS = {'count': 2, 'observed': [], 'count_basis': 'normalized-native-parameters'}
EMPTY_SHA256 = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'


def validate_crypto_input(value):
    """Validate the observation shape; a fingerprint does not prove completion."""
    common = {'type', 'boundary', 'algorithm', 'fingerprint_algorithm',
              'byte_length', 'proves_async_completion'}
    if not isinstance(value, dict) or set(value) not in (common | {'sha256'}, common | {'omitted'}):
        raise ValueError('invalid hashing input fields')
    if (value['type'] != 'crypto-input' or value['boundary'] != BOUNDARY or
            value['algorithm'] not in ('SHA-1', 'SHA-256', 'SHA-384', 'SHA-512') or
            value['fingerprint_algorithm'] != 'SHA-256' or
            value['proves_async_completion'] is not False):
        raise ValueError('invalid hashing input classification')
    # Native size_t is transported as an exact string, independently of JSON's
    # floating-point readers. The supported 64-bit native build cannot exceed it.
    length = value['byte_length']
    if (not isinstance(length, str) or not re.fullmatch(r'0|[1-9][0-9]{0,19}', length)
            or int(length) > 2**64 - 1):
        raise ValueError('invalid hashing input length')
    length = int(length)
    if 'sha256' in value:
        digest = value['sha256']
        if (length > MAX_INPUT_BYTES or not isinstance(digest, str) or
                not re.fullmatch('[0-9a-f]{64}', digest) or
                (length == 0 and digest != EMPTY_SHA256)):
            raise ValueError('invalid hashing input fingerprint')
    elif value['omitted'] != ('length-limit' if length > MAX_INPUT_BYTES else 'digest-unavailable'):
        raise ValueError('invalid hashing input omission')
    return value


def validate_crypto_parameters(value):
    if (not isinstance(value, dict) or value != PARAMETERS or
            type(value.get('count')) is not int):
        raise ValueError('invalid normalized hashing input parameters')
