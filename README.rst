=====
hkdfs
=====

HMAC-based key derivation function (HKDF) standalone implementation using pure Python.

Description and Purpose 
-----------------------
This library contains a pure-Python implementation of the HMAC-based key derivation function (HKDF) as specified in `RFC 5869 <https://www.rfc-editor.org/rfc/rfc5869>`__. The order and names of arguments within the function signatures in this implementation deviate from the specification in order to adhere more closely to typical Python conventions (such as having arguments with default values follow arguments without default values).

This library has been created and is maintained because other standalone implementations (such as the `hkdf <https://pypi.org/project/hkdf/>`__ package) are not actively maintained and `implementations <https://cryptography.io/en/latest/hazmat/primitives/key-derivation-functions/#hkdf>`__ available in larger libraries such as `cryptography <https://cryptography.io/>`__ are not standalone.

Usage
-----
The library can be imported in the usual manner:

.. code-block:: python

    import hkdfs
    from hkdfs import hkdfs

Examples
^^^^^^^^
A basic usage example is provided below:

.. code-block:: python

    >>> hkdfs(1024, bytes([1]), bytes([2]), bytes([3])).hex()[:73]
    '1277a50c8cd05020dc073bd129cd84214270a0468e936c496fafee48c10a613a1a3b10fd2'

Acknowledgments
^^^^^^^^^^^^^^^
Materials consulted throughout the implementation of this library include `RFC 5869 <https://www.rfc-editor.org/rfc/rfc5869>`__ and the example implementation in the `Wikipedia article about the HKDF function <https://en.wikipedia.org/wiki/HKDF>`__.

Contributions
^^^^^^^^^^^^^
In order to contribute to the source code, open an issue or submit a pull request on the `GitHub page <https://github.com/nillionnetwork/hkdfs>`__ for this library.

Versioning
^^^^^^^^^^
The version number format for this library and the changes to the library associated with version number increments conform with `Semantic Versioning 2.0.0 <https://semver.org/#semantic-versioning-200>`__.
