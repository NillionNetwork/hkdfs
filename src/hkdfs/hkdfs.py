"""
HMAC-based key derivation function (HKDF) standalone implementation using pure
Python.
"""
from __future__ import annotations
from typing import Union, Optional, Callable
import doctest
import hashlib
import hmac

_HASH: Callable[[Union[bytes, bytearray]], hashlib._hashlib.HASH] = \
    hashlib.sha256
"""Hash function used for HKDF and matching."""

def _hkdf_extract(
        input_key_material: Union[bytes, bytearray],
        salt: Optional[Union[bytes, bytearray]] = None,
    ) -> bytes:
    """
    Extract a pseudorandom key (PRK) using HMAC with the given input key
    material and salt. If the salt is empty, a zero-filled byte string (of
    the same length as the hash function's digest) is used.

    :param input_key_material: Initial key material.
    :param salt: Additional salt to incorporate during extraction.
    """
    return hmac.new(
        salt or bytes([0] * _HASH().digest_size),
        input_key_material,
        _HASH
    ).digest()

def _hkdf_expand(
        length: int,
        pseudorandom_key: Union[bytes, bytearray],
        info: Optional[Union[bytes, bytearray]] = None
    ) -> bytes:
    """
    Expand the supplied pseudorandom key into output key material of the
    specified length using HMAC-based expansion.

    :param length: Target length of output key.
    :param pseudorandom_key: Pseudorandom key to expand.
    :param info: Additional binary data to incorporate during expansion.
    """
    info = info or bytes()
    digest = bytes()
    output_key_material = bytes()
    i = 0
    while len(output_key_material) < length:
        i += 1
        digest = hmac.new(
            pseudorandom_key,
            digest + info + bytes([i]),
            _HASH
        ).digest()
        output_key_material += digest

    return output_key_material[:length]

def hkdfs(
        length: int,
        key: Union[bytes, bytearray],
        salt: Optional[Union[bytes, bytearray]] = None,
        info: Optional[Union[bytes, bytearray]] = None
    ) -> bytes:
    """
    Extract a pseudorandom key having ``length`` bytes from ``key`` (and
    optionally also from ``salt`` and ``info``).

    :param length: Target length of output key.
    :param key: Pseudorandom key to expand.
    :param salt: Additional salt to incorporate during extraction.
    :param info: Additional binary data to incorporate.

    >>> hkdfs(1024, bytes([123])).hex()
    'bd54b22aa1447254436981928dc26b3bdce...393295e453c86663d613b2481b0c1184714'
    >>> hkdfs(1024, bytes([1]), bytes([2]), bytes([3])).hex()[:73]
    '04de356fb510a12615c21c4fd98a0ddc67e5d35ce0d36a296f435b7cd5e48ec54c9d438d8'
    """
    return _hkdf_expand(length, _hkdf_extract(key, salt), info)

if __name__ == '__main__':
    doctest.testmod() # pragma: no cover
