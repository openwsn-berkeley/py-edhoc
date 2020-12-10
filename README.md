# py-edhoc:snake: --  Ephemeral Diffie-Hellman Over COSE
This project provides a Python implementation of the EDHOC key exchange protocol for constrained devices. 
Currently the protocol is still in [draft](https://datatracker.ietf.org/doc/draft-ietf-lake-edhoc/) status at the IETF.

The repository provides an implementation of:
  * <s>[https://datatracker.ietf.org/doc/html/draft-ietf-lake-edhoc-01](https://datatracker.ietf.org/doc/html/draft-ietf-lake-edhoc-01)</s>
  * [https://datatracker.ietf.org/doc/html/draft-ietf-lake-edhoc-02](https://datatracker.ietf.org/doc/html/draft-ietf-lake-edhoc-02)
  
## Installation

```bash
$ pip install edhoc
```
## Supported Cipher Suites
|  **Cipher Suites**  |     **Support**    |
|:-------------------:|:------------------:|
| *SUITE 0*           | :heavy_check_mark: |
| *SUITE 1*           | :heavy_check_mark: |
| *SUITE 2*           |         :x:        | 
| *SUITE 3*           |         :x:        | 

## Authentication Methods

## Supported Cipher Suites
|      **Method**     |     **Support**    |
|:-------------------:|:------------------:|
| *SIGN-SIGN*         | :heavy_check_mark: |
| *STATIC-SIGN*       | :heavy_check_mark: |
| *SIGN-STATIC*       | :heavy_check_mark: | 
| *STATIC-STATIC*     | :heavy_check_mark: | 

# Cryptography
The project depends on the python `cose` package. `cose` uses [pyca/cryptography](https://github.com/pyca/cryptography) for all cryptographic operations, except the deterministic ECDSA algorithm. For deterministic ECDSA `ocse` uses [python-ecdsa](https://github.com/warner/python-ecdsa). 
