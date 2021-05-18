from abc import ABC, abstractmethod
from enum import IntEnum, unique
from typing import Callable, Any, TypeVar, NamedTuple

import cbor2
from cose.algorithms import AESCCM1664128, Sha256, EdDSA, AESCCM16128128, Es256, A128GCM, A256GCM, Sha384, Es384
from cose.curves import X25519, Ed25519, P256, P384

from edhoc.exceptions import EdhocException


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
                cls.dh_curve.identifier,
                cls.sign_alg.identifier,
                cls.sign_curve.identifier,
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

@CipherSuite.register_ciphersuite()
class CipherSuite4(CipherSuite):
    identifier = 4
    fullname = "SUITE_4"

    aead = A128GCM
    hash = Sha256
    dh_curve = X25519
    sign_alg = Es256
    sign_curve = P256
    app_aead = A128GCM
    app_hash = Sha256
assert CipherSuite4.check_identifiers() == (1, -16, 4, -7, 1, 1, -16)

@CipherSuite.register_ciphersuite()
class CipherSuite5(CipherSuite):
    identifier = 5
    fullname = "SUITE_5"

    aead = A256GCM
    hash = Sha384
    dh_curve = P384
    sign_alg = Es384
    sign_curve = P384
    app_aead = A256GCM
    app_hash = Sha384
assert CipherSuite5.check_identifiers() == (3, -43, 2, -35, 2, 3, -43)


class EdhocKDFInfo(NamedTuple):
    edhoc_aead_id: int
    transcript_hash: bytes
    label: str
    length: int

    def encode(self) -> bytes:
        info = [self.edhoc_aead_id, self.transcript_hash, self.label, self.length]
        info = cbor2.dumps(info)
        return info


CS = TypeVar('CS', bound='CipherSuite')

if __name__ == "__main__":
    print(CipherSuite.get_registered_ciphersuites())
