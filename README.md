# py-edhoc:snake: --  Ephemeral Diffie-Hellman Over COSE
![Python package](https://github.com/openwsn-berkeley/py-edhoc/workflows/Python%20package/badge.svg)
![Python 3.6+](https://img.shields.io/badge/python-3.6%2B-blue)

This project provides a Python implementation of the EDHOC key exchange protocol for constrained devices. 
Currently the protocol is still in [draft](https://datatracker.ietf.org/doc/draft-ietf-lake-edhoc/) status at the IETF.

The repository provides an implementation of:
  * <s>[https://datatracker.ietf.org/doc/html/draft-ietf-lake-edhoc-01](https://datatracker.ietf.org/doc/html/draft-ietf-lake-edhoc-01)</s>
  * [https://datatracker.ietf.org/doc/html/draft-ietf-lake-edhoc-02](https://datatracker.ietf.org/doc/html/draft-ietf-lake-edhoc-02)
  
## Installation

```bash
$ pip install edhoc
```

## Running the test suite
The `py-edhoc` test suite is based on the [official test vectors](https://github.com/lake-wg/edhoc/blob/master/test-vectors/vectors.txt) provided by the LAKE working group.

To run the test suite you'll need `pytest`:

```bash
$ pip install pytest
```

When you move to the root of the `py-edhoc` project you can run the test by simply typing:

```bash
$ pytest
```


## Supported Cipher Suites
|  **Cipher Suites**  |                                **COSE algorithms**                              |     **Support**    |
|:-------------------:|:-------------------------------------------------------------------------------:|:------------------:|
| *SUITE 0*           |(AES-CCM-16-64-128, SHA-256, X25519, EdDSA, Ed25519, AES-CCM-16-64-128, SHA-256) | :heavy_check_mark: |
| *SUITE 1*           |(AES-CCM-16-128-128, SHA-256, X25519, EdDSA, Ed25519, AES-CCM-16-64-128, SHA-256)| :heavy_check_mark: |
| *SUITE 2*           |(AES-CCM-16-64-128, SHA-256, P-256, ES256, P-256, AES-CCM-16-64-128, SHA-256)    |         :x:        |
| *SUITE 3*           | (AES-CCM-16-128-128, SHA-256, P-256, ES256, P-256, AES-CCM-16-64-128, SHA-256)  |         :x:        |

## Authentication Methods
|      **Method**     |     **Support**    |
|:-------------------:|:------------------:|
| *SIGN-SIGN*         | :heavy_check_mark: |
| *STATIC-SIGN*       | :heavy_check_mark: |
| *SIGN-STATIC*       | :heavy_check_mark: |
| *STATIC-STATIC*     | :heavy_check_mark: |

# Cryptography
The project depends on the python `cose` package. `cose` uses [pyca/cryptography](https://github.com/pyca/cryptography) for all cryptographic operations, except the deterministic ECDSA algorithm. For deterministic ECDSA `cose` uses [python-ecdsa](https://github.com/warner/python-ecdsa). 
