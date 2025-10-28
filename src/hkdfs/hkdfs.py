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

    The below tests correspond to the test cases found in Appendix A of
    `RFC 5869 <https://www.rfc-editor.org/rfc/rfc5869>`__.

    >>> hkdfs( # Test Case 1: Basic test case with SHA-256
    ...     length=42,
    ...     key=bytes.fromhex('0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b'),
    ...     salt=bytes.fromhex('000102030405060708090a0b0c'),
    ...     info=bytes.fromhex('f0f1f2f3f4f5f6f7f8f9'),
    ...     hash=hashlib.sha256
    ... ).hex() == (
    ...     '3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf' +
    ...     '1a5a4c5db02d56ecc4c5bf34007208d5b887185865'
    ... )
    True
    >>> hkdfs( # Test Case 2: Test with SHA-256 and longer inputs/outputs
    ...     length=82,
    ...     key=bytes.fromhex(
    ...         '000102030405060708090a0b0c0d0e0f' +
    ...         '101112131415161718191a1b1c1d1e1f' +
    ...         '202122232425262728292a2b2c2d2e2f' +
    ...         '303132333435363738393a3b3c3d3e3f' +
    ...         '404142434445464748494a4b4c4d4e4f'
    ...     ),
    ...     salt=bytes.fromhex(
    ...         '606162636465666768696a6b6c6d6e6f' +
    ...         '707172737475767778797a7b7c7d7e7f' +
    ...         '808182838485868788898a8b8c8d8e8f' +
    ...         '909192939495969798999a9b9c9d9e9f' +
    ...         'a0a1a2a3a4a5a6a7a8a9aaabacadaeaf'
    ...     ),
    ...     info=bytes.fromhex(
    ...         'b0b1b2b3b4b5b6b7b8b9babbbcbdbebf' +
    ...         'c0c1c2c3c4c5c6c7c8c9cacbcccdcecf' +
    ...         'd0d1d2d3d4d5d6d7d8d9dadbdcdddedf' +
    ...         'e0e1e2e3e4e5e6e7e8e9eaebecedeeef' +
    ...         'f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff'
    ...     ),
    ...     hash=hashlib.sha256
    ... ).hex() == (
    ...     'b11e398dc80327a1c8e7f78c596a49344f012eda2d4efad8a050cc4c19afa97' +
    ...     'c59045a99cac7827271cb41c65e590e09da3275600c2f09b8367793a9aca3db' +
    ...     '71cc30c58179ec3e87c14c01d5c1f3434f1d87'
    ... )
    True
    >>> hkdfs( # Test Case 3: Test with SHA-256 and zero-length salt/info
    ...     length=42,
    ...     key=bytes.fromhex('0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b'),
    ...     salt=bytes(0),
    ...     info=bytes(0),
    ...     hash=hashlib.sha256
    ... ).hex() == (
    ...     '8da4e775a563c18f715f802a063c5a31b8a11f5c5e' +
    ...     'e1879ec3454e5f3c738d2d9d201395faa4b61a96c8'
    ... )
    True
    >>> hkdfs( # Test Case 4: Basic test case with SHA-1
    ...     length=42,
    ...     key=bytes.fromhex('0b0b0b0b0b0b0b0b0b0b0b'),
    ...     salt=bytes.fromhex('000102030405060708090a0b0c'),
    ...     info=bytes.fromhex('f0f1f2f3f4f5f6f7f8f9'),
    ...     hash=hashlib.sha1
    ... ).hex() == (
    ...     '085a01ea1b10f36933068b56efa5ad81a4f14b822f' +
    ...     '5b091568a9cdd4f155fda2c22e422478d305f3f896'
    ... )
    True
    >>> hkdfs( # Test Case 5: Test with SHA-1 and longer inputs/outputs
    ...     length=82,
    ...     key=bytes.fromhex(
    ...         '000102030405060708090a0b0c0d0e0f' +
    ...         '101112131415161718191a1b1c1d1e1f' +
    ...         '202122232425262728292a2b2c2d2e2f' +
    ...         '303132333435363738393a3b3c3d3e3f' +
    ...         '404142434445464748494a4b4c4d4e4f'
    ...     ),
    ...     salt=bytes.fromhex(
    ...         '606162636465666768696a6b6c6d6e6f' +
    ...         '707172737475767778797a7b7c7d7e7f' +
    ...         '808182838485868788898a8b8c8d8e8f' +
    ...         '909192939495969798999a9b9c9d9e9f' +
    ...         'a0a1a2a3a4a5a6a7a8a9aaabacadaeaf'
    ...     ),
    ...     info=bytes.fromhex(
    ...         'b0b1b2b3b4b5b6b7b8b9babbbcbdbebf' +
    ...         'c0c1c2c3c4c5c6c7c8c9cacbcccdcecf' +
    ...         'd0d1d2d3d4d5d6d7d8d9dadbdcdddedf' +
    ...         'e0e1e2e3e4e5e6e7e8e9eaebecedeeef' +
    ...         'f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff'
    ...     ),
    ...     hash=hashlib.sha1
    ... ).hex() == (
    ...     '0bd770a74d1160f7c9f12cd5912a06ebff6adcae899d92191fe4305673ba2ff' +
    ...     'e8fa3f1a4e5ad79f3f334b3b202b2173c486ea37ce3d397ed034c7f9dfeb15c' +
    ...     '5e927336d0441f4c4300e2cff0d0900b52d3b4'
    ... )
    True
    >>> hkdfs( # Test Case 6: Test with SHA-1 and zero-length salt/info
    ...     length=42,
    ...     key=bytes.fromhex('0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b'),
    ...     salt=bytes(0),
    ...     info=bytes(0),
    ...     hash=hashlib.sha1
    ... ).hex() == (
    ...     '0ac1af7002b3d761d1e55298da9d0506b9ae520572' +
    ...     '20a306e07b6b87e8df21d0ea00033de03984d34918'
    ... )
    True
    >>> hkdfs( # Test Case 7: Test with SHA-1, no salt, and zero-length info
    ...     length=42,
    ...     key=bytes.fromhex('0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c'),
    ...     info=bytes(0),
    ...     hash=hashlib.sha1
    ... ).hex() == (
    ...     '2c91117204d745f3500d636a62f64f0ab3bae548aa' +
    ...     '53d423b0d1f27ebba6f5e5673a081d70cce7acfc48'
    ... )
    True

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
