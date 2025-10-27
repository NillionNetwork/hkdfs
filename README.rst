=====
hkdfs
=====

HMAC-based key derivation function (HKDF) standalone implementation using pure Python.

|pypi| |readthedocs| |actions| |coveralls|

.. |pypi| image:: https://badge.fury.io/py/hkdfs.svg#
   :target: https://badge.fury.io/py/hkdfs
   :alt: PyPI version and link.

.. |readthedocs| image:: https://readthedocs.org/projects/hkdfs/badge/?version=latest
   :target: https://hkdfs.readthedocs.io/en/latest/?badge=latest
   :alt: Read the Docs documentation status.

.. |actions| image:: https://github.com/nillionnetwork/hkdfs/workflows/lint-test-cover-docs/badge.svg#
   :target: https://github.com/nillionnetwork/hkdfs/actions/workflows/lint-test-cover-docs.yml
   :alt: GitHub Actions status.

.. |coveralls| image:: https://coveralls.io/repos/github/NillionNetwork/hkdfs/badge.svg?branch=main
   :target: https://coveralls.io/github/NillionNetwork/hkdfs?branch=main
   :alt: Coveralls test coverage summary.

Description and Purpose 
-----------------------
This library contains a pure-Python implementation of the HMAC-based key derivation function (HKDF) as specified in `RFC 5869 <https://www.rfc-editor.org/rfc/rfc5869>`__. The order and names of arguments within the function signatures in this implementation deviate from the specification in order to adhere more closely to typical Python conventions (such as having arguments with default values follow arguments without default values).

This library has been created and is maintained because other standalone implementations (such as the `hkdf <https://pypi.org/project/hkdf/>`__ package) are not actively maintained and `implementations <https://cryptography.io/en/latest/hazmat/primitives/key-derivation-functions/#hkdf>`__ available in larger libraries such as `cryptography <https://cryptography.io/>`__ are not standalone.

Installation and Usage
----------------------
This library is available as a `package on PyPI <https://pypi.org/project/hkdfs>`__:

.. code-block:: bash

    python -m pip install hkdfs

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

Development
-----------
All installation and development dependencies are fully specified in ``pyproject.toml``. The ``project.optional-dependencies`` object is used to `specify optional requirements <https://peps.python.org/pep-0621>`__ for various development tasks. This makes it possible to specify additional options (such as ``docs``, ``lint``, and so on) when performing installation using `pip <https://pypi.org/project/pip>`__:

.. code-block:: bash

    python -m pip install ".[docs,lint]"

Documentation
^^^^^^^^^^^^^
The documentation can be generated automatically from the source files using `Sphinx <https://www.sphinx-doc.org>`__:

.. code-block:: bash

    python -m pip install ".[docs]"
    cd docs
    sphinx-apidoc -f -E --templatedir=_templates -o _source .. && make html

Testing and Conventions
^^^^^^^^^^^^^^^^^^^^^^^
All unit tests are executed and their coverage is measured when using `pytest <https://docs.pytest.org>`__ (see the ``pyproject.toml`` file for configuration details):

.. code-block:: bash

    python -m pip install ".[test]"
    python -m pytest

The subset of the unit tests included in the module itself and can be executed using `doctest <https://docs.python.org/3/library/doctest.html>`__:

.. code-block:: bash

    python src/hkdfs/hkdfs.py -v

Style conventions are enforced using `Pylint <https://pylint.readthedocs.io>`__:

.. code-block:: bash

    python -m pip install ".[lint]"
    python -m pylint src/hkdfs

Acknowledgments
^^^^^^^^^^^^^^^
Materials consulted throughout the implementation of this library include `RFC 5869 <https://www.rfc-editor.org/rfc/rfc5869>`__ and the example implementation in the `Wikipedia article about the HKDF function <https://en.wikipedia.org/wiki/HKDF>`__.

Contributions
^^^^^^^^^^^^^
In order to contribute to the source code, open an issue or submit a pull request on the `GitHub page <https://github.com/nillionnetwork/hkdfs>`__ for this library.

Versioning
^^^^^^^^^^
The version number format for this library and the changes to the library associated with version number increments conform with `Semantic Versioning 2.0.0 <https://semver.org/#semantic-versioning-200>`__.

Publishing
^^^^^^^^^^
This library can be published as a `package on PyPI <https://pypi.org/project/hkdfs>`__ via the GitHub Actions workflow found in ``.github/workflows/build-publish-sign-release.yml`` that follows the `recommendations found in the Python Packaging User Guide <https://packaging.python.org/en/latest/guides/publishing-package-distribution-releases-using-github-actions-ci-cd-workflows/>`__.

Ensure that the correct version number appears in ``pyproject.toml``, and that any links in this README document to the Read the Docs documentation of this package (or its dependencies) have appropriate version numbers. Also ensure that the Read the Docs project for this library has an `automation rule <https://docs.readthedocs.io/en/stable/automation-rules.html>`__ that activates and sets as the default all tagged versions.

To publish the package, create and push a tag for the version being published (replacing ``?.?.?`` with the version number):

.. code-block:: bash

    git tag ?.?.?
    git push origin ?.?.?
