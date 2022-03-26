from abc import ABC, abstractmethod
from enum import IntEnum, unique
from typing import Callable, Any, TypeVar, NamedTuple

import cbor2
from cose.algorithms import AESCCM1664128, Sha256, EdDSA, AESCCM16128128, Es256, A128GCM, A256GCM, Sha384, Es384
from cose.keys.curves import X25519, Ed25519, P256, P384
from cose.keys import CoseKey

from edhoc.exceptions import EdhocException


def cborstream(items) -> bytes:
    """Encode an iterable of items in CBOR into a stream"""
    return b"".join(cbor2.dumps(i) for i in items)

def compress_id_cred_x(id_cred_x):
    if list(id_cred_x.keys()) == 4 and type(id_cred_x[4]) in (int, bytes):
        return id_cred_x[4]
    else:
        return id_cred_x

def bytewise_xor(a: bytes, b: bytes) -> bytes:
    assert len(a) == len(b) # Python 3.10: zip(a, b, True) and remove this line
    return bytes((_a ^ _b) for (_a, _b) in zip(a, b))

class EdhocState(IntEnum):
    EDHOC_WAIT = 0
    MSG_1_SENT = 1
    MSG_1_RCVD = 2
    MSG_2_SENT = 3
    MSG_2_RCVD = 4
    MSG_3_SENT = 5
    MSG_3_RCVD = 6
    EDHOC_SUCC = 7
    EDHOC_FAIL = 8


class Method(IntEnum):
    """ Enumerations for the EHDOC method types. """

    # Initiator - Responder
    SIGN_SIGN = 0
    SIGN_STATIC = 1
    STATIC_SIGN = 2
    STATIC_STATIC = 3


@unique
class Correlation(IntEnum):
    CORR_0 = 0
    CORR_1 = 1
    CORR_2 = 2
    CORR_3 = 3


class CipherSuite(ABC):
    _registered_ciphersuites = {}

    @classmethod
    def default_parser(cls, value):
        return value

    value_parser: Callable = default_parser

    @classmethod
    def get_registered_ciphersuites(cls):
        return cls._registered_ciphersuites

    @classmethod
    def register_ciphersuite(cls) -> Callable:
        def decorator(the_class: 'CipherSuite'):
            cls.get_registered_ciphersuites()[the_class.identifier] = the_class
            cls.get_registered_ciphersuites()[the_class.fullname] = the_class
            return the_class

        return decorator

    @classmethod
    def from_id(cls, identifier: Any) -> Any:
        if isinstance(identifier, int) and identifier in cls.get_registered_ciphersuites():
            return cls.get_registered_ciphersuites()[identifier]
        elif isinstance(identifier, str) and identifier in cls.get_registered_ciphersuites():
            return cls.get_registered_ciphersuites()[identifier.upper()]
        elif hasattr(identifier, 'identifier') and identifier.identifier in cls.get_registered_ciphersuites():
            return cls.get_registered_ciphersuites()[identifier.identifier]
        else:
            raise EdhocException(f"Unknown EDHOC cipher suite: {identifier}")

    @property
    @abstractmethod
    def identifier(self):
        raise NotImplementedError()

    @property
    @abstractmethod
    def fullname(self) -> str:
        raise NotImplementedError()

    def __int__(self):
        return self.identifier

    def __str__(self):
        return self.fullname

    def __eq__(self, other: 'CipherSuite'):
        return self.identifier == other.identifier

    def __ne__(self, other: 'CipherSuite'):
        return self.identifier != other.identifier

    def __lt__(self, other: 'CipherSuite'):
        return self.identifier < other.identifier

    def __le__(self, other: 'CipherSuite'):
        return self.identifier <= other.identifier

    def __gt__(self, other: 'CipherSuite'):
        return self.identifier > other.identifier

    def __ge__(self, other: 'CipherSuite'):
        return self.identifier >= other.identifier

    def __repr__(self):
        return f'<{self.fullname}: {self.identifier}>'

    @classmethod
    def check_identifiers(cls):
        """Return the algorithm names for the suite in the sequence in which
        they are printed in the EDHOC specification, for easy validation of the
        classes."""
        return (
                cls.aead.identifier,
                cls.hash.identifier,
                cls.edhoc_mac_length,
                cls.dh_curve.identifier,
                cls.sign_alg.identifier,
                cls.app_aead.identifier,
                cls.app_hash.identifier,
                )


@CipherSuite.register_ciphersuite()
class CipherSuite0(CipherSuite):
    identifier = 0
    fullname = "SUITE_0"

    aead = AESCCM1664128
    hash = Sha256
    dh_curve = X25519
    sign_alg = EdDSA
    sign_curve = Ed25519
    app_aead = AESCCM1664128
    app_hash = Sha256

    edhoc_mac_length = 8
assert CipherSuite0.check_identifiers() == (10, -16, 8, 4, -8, 10, -16)


@CipherSuite.register_ciphersuite()
class CipherSuite1(CipherSuite):
    identifier = 1
    fullname = "SUITE_1"

    aead = AESCCM16128128
    hash = Sha256
    dh_curve = X25519
    sign_alg = EdDSA
    sign_curve = Ed25519
    app_aead = AESCCM1664128
    app_hash = Sha256

    edhoc_mac_length = 16
assert CipherSuite1.check_identifiers() == (30, -16, 16, 4, -8, 10, -16)


@CipherSuite.register_ciphersuite()
class CipherSuite2(CipherSuite):
    identifier = 2
    fullname = "SUITE_2"

    aead = AESCCM1664128
    hash = Sha256
    dh_curve = P256
    sign_alg = Es256
    sign_curve = P256
    app_aead = AESCCM1664128
    app_hash = Sha256

    edhoc_mac_length = 8
assert CipherSuite2.check_identifiers() == (10, -16, 8, 1, -7, 10, -16)


@CipherSuite.register_ciphersuite()
class CipherSuite3(CipherSuite):
    identifier = 3
    fullname = "SUITE_3"

    aead = AESCCM16128128
    hash = Sha256
    dh_curve = P256
    sign_alg = Es256
    sign_curve = P256
    app_aead = AESCCM1664128
    app_hash = Sha256

    edhoc_mac_length = 16
assert CipherSuite3.check_identifiers() == (30, -16, 16, 1, -7, 10, -16)

# ChaCha missing from pycose

@CipherSuite.register_ciphersuite()
class CipherSuite6(CipherSuite):
    identifier = 6
    fullname = "SUITE_6"

    aead = A128GCM
    hash = Sha256
    dh_curve = X25519
    sign_alg = Es256
    sign_curve = P256
    app_aead = A128GCM
    app_hash = Sha256

    edhoc_mac_length = 16
assert CipherSuite6.check_identifiers() == (1, -16, 16, 4, -7, 1, -16)

@CipherSuite.register_ciphersuite()
class CipherSuite24(CipherSuite):
    identifier = 24
    fullname = "SUITE_24"

    aead = A256GCM
    hash = Sha384
    dh_curve = P384
    sign_alg = Es384
    sign_curve = P384
    app_aead = A256GCM
    app_hash = Sha384

    edhoc_mac_length = 16
assert CipherSuite24.check_identifiers() == (3, -43, 16, 2, -35, 3, -43)


class EdhocKDFInfo(NamedTuple):
    transcript_hash: bytes
    label: str
    context: bytes
    length: int

    def encode(self) -> bytes:
        return cborstream(self)

class CCS:
    """A CWT Claims Set (containing an unencrypted COSE key in its CNF)"""
    def __init__(self, encoded: bytes):
        """Decode a CWT. Raises some ValueError if the set can not be
        decoded."""
        self.encoded = encoded
        self._set_details_from(cbor2.loads(encoded))

    @classmethod
    def from_unencoded(cls, unencoded: dict):
        """Load a CWT from a dictionary that all parties agree to encoded
        canonically"""
        # The optimization of going directly to _set_details is probably
        # unwarranted.
        return cls(cbor2.dumps(unencoded))

    def _set_details_from(self, d: dict):
        CWT_SUB = 2
        CWT_CNF = 8
        CNF_KEY = 1
        self.sub = d.get(CWT_SUB, None)
        cnf = d[CWT_CNF]
        key = cnf[CNF_KEY]
        self.key = CoseKey.from_dict(key)

CS = TypeVar('CS', bound='CipherSuite')

if __name__ == "__main__":
    print(CipherSuite.get_registered_ciphersuites())
