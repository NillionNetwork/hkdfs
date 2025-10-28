"""
HMAC-based key derivation function (HKDF) standalone implementation using pure
Python.
"""
from __future__ import annotations
from typing import Union, Optional
from collections.abc import Callable
import doctest
import hashlib
import hmac

def _hkdf_extract(
        input_key_material: Union[bytes, bytearray],
        salt: Optional[Union[bytes, bytearray]] = None,
        hash: Callable[ # pylint: disable=redefined-builtin
            [Union[bytes, bytearray]],
            hashlib._hashlib.HASH
        ] = hashlib.sha256
    ) -> bytes:
    """
    Extract a pseudorandom key (PRK) using HMAC with the given input key
    material and salt. If the salt is empty, a zero-filled byte string (of
    the same length as the hash function's digest) is used.

    :param input_key_material: Initial key material.
    :param salt: Additional salt to incorporate during extraction.
    :param hash: Hash function to use when performing the extraction.
    """
    return hmac.new(
        salt or bytes([0] * hash().digest_size),
        input_key_material,
        hash
    ).digest()

def _hkdf_expand(
        length: int,
        pseudorandom_key: Union[bytes, bytearray],
        info: Optional[Union[bytes, bytearray]] = None,
        hash: Callable[ # pylint: disable=redefined-builtin
            [Union[bytes, bytearray]],
            hashlib._hashlib.HASH
        ] = hashlib.sha256
    ) -> bytes:
    """
    Expand the supplied pseudorandom key into output key material of the
    specified length using HMAC-based expansion.

    :param length: Target length of output key.
    :param pseudorandom_key: Pseudorandom key to expand.
    :param info: Additional binary data to incorporate during expansion.
    :param hash: Hash function to use when performing the extraction.
    """
    length_maximum = 255 * hash().digest_size
    if length > length_maximum:
        raise ValueError(
            'maximum length supported by supplied hash function is ' +
            str(length_maximum)
        )

    info = info or bytes()
    digest = bytes()
    output_key_material = bytes()
    i = 0
    while len(output_key_material) < length:
        i += 1
        digest = hmac.new(
            pseudorandom_key,
            digest + info + bytes([i]),
            hash
        ).digest()
        output_key_material += digest

    return output_key_material[:length]

def hkdfs(
        length: int,
        key: Union[bytes, bytearray],
        salt: Optional[Union[bytes, bytearray]] = None,
        info: Optional[Union[bytes, bytearray]] = None,
        hash: Callable[ # pylint: disable=redefined-builtin
            [Union[bytes, bytearray]],
            hashlib._hashlib.HASH
        ] = hashlib.sha256
    ) -> bytes:
    """
    Extract a pseudorandom key having ``length`` bytes from ``key`` (and
    optionally also from ``salt`` and ``info``).

    :param length: Target length of output key.
    :param key: Pseudorandom key to expand.
    :param salt: Additional salt to incorporate during extraction.
    :param info: Additional binary data to incorporate during expansion.

    >>> hkdfs(1024, bytes([123]), hash=hashlib.sha512).hex()
    '4936e6f3ad5e6cab0efd42e2f216d34b977...1bc59c8e55db51d239808e8465a3cb91d11'
    >>> hkdfs(
    ...     length=1024,
    ...     key=bytes([1]), 
    ...     salt=bytes([2]),
    ...     info=bytes([3]),
    ...     hash=hashlib.sha512
    ... ).hex()[:73]
    '1277a50c8cd05020dc073bd129cd84214270a0468e936c496fafee48c10a613a1a3b10fd2'

    Note that the maximum supported target length is determined by the length
    of the output of the supplied hash function.

    >>> hkdfs(255 * 32 + 1, bytes([123]), hash=hashlib.sha256)
    Traceback (most recent call last):
      ...
    ValueError: maximum length supported by supplied hash function is 8160
    >>> len(hkdfs(255 * 32 + 1, bytes([123]), hash=hashlib.sha512))
    8161
    >>> hkdfs(255 * 64 + 1, bytes([123]), hash=hashlib.sha512)
    Traceback (most recent call last):
      ...
    ValueError: maximum length supported by supplied hash function is 16320

    This function performs type and range checking, raising an exception when
    invoked with invalid arguments.

    >>> hkdfs('abc', bytes([1]))
    Traceback (most recent call last):
      ...
    TypeError: length must be an integer
    >>> hkdfs(-1, bytes([1]))
    Traceback (most recent call last):
      ...
    ValueError: length must be a nonnegative integer
    >>> hkdfs(1024, 'abc')
    Traceback (most recent call last):
      ...
    TypeError: key must be a bytes-like object
    >>> hkdfs(1024, bytes([1]), 'abc')
    Traceback (most recent call last):
      ...
    TypeError: salt must be a bytes-like object
    >>> hkdfs(1024, bytes([1]), bytes([2]), 'abc')
    Traceback (most recent call last):
      ...
    TypeError: info must be a bytes-like object

    The final optional argument ``hash`` is normally expected be a valid hash
    function from the built-in :obj:`hashlib` module (for example, the function
    :obj:`hashlib.sha512`). However, any object that matches the interface of
    the example class ``digestmod`` below can be supplied.

    >>> class digestmod:
    ...     digest_size: int = 64
    ...     block_size: int = 64
    ...
    ...     def update(d: digestmod, b: bytes):
    ...         pass
    ...
    ...     def copy(self: digestmod) -> digestmod:
    ...         return digestmod()
    ...
    ...     def digest(self: digestmod) -> bytes:
    ...         return bytes(64)
    ...
    >>> hkdfs(1024, bytes([123]), hash=digestmod) == bytes(1024)
    True

    No checks are performed to confirm that the supplied value for ``hash``
    conforms to the above interface. A deviation from this interface may cause
    an exception to be raised by an underlying internal or built-in function.
    This exception will either be a :obj:`TypeError` because the value is
    not callable, an :obj:`AttributeError` because an expected attribute is
    missing, or another error because the attributes do not behave as would
    be expected for a built-in hash function.

    >>> hkdfs(1024, bytes([123]), hash=123)
    Traceback (most recent call last):
      ...
    TypeError: 'int' object is not callable
    >>> class digestmod:
    ...     digest_size: int = 64
    ...     block_size: int = 64
    ...
    >>> hkdfs(1024, bytes([123]), hash=digestmod)
    Traceback (most recent call last):
      ...
    AttributeError: 'digestmod' object has no attribute 'update'

    Consult the documentation for :obj:`hashlib.new` for more information.
    """
    if not isinstance(length, int):
        raise TypeError('length must be an integer')

    if not isinstance(key, (bytes, bytearray)):
        raise TypeError('key must be a bytes-like object')

    if salt is not None and not isinstance(salt, (bytes, bytearray)):
        raise TypeError('salt must be a bytes-like object')

    if info is not None and not isinstance(info, (bytes, bytearray)):
        raise TypeError('info must be a bytes-like object')

    if length < 0:
        raise ValueError('length must be a nonnegative integer')

    return _hkdf_expand(length, _hkdf_extract(key, salt, hash), info, hash)

if __name__ == '__main__':
    doctest.testmod() # pragma: no cover
