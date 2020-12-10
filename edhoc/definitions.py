from typing import NamedTuple

import cbor2
from aenum import unique, IntEnum, Enum, MultiValue, skip
from cose import CoseAlgorithms, CoseEllipticCurves
from dataclasses import dataclass


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


@unique
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


class _CipherSetup(NamedTuple):
    aead: CoseAlgorithms
    hash: CoseAlgorithms
    dh_curve: CoseEllipticCurves
    sign_alg: CoseAlgorithms
    sign_curve: CoseEllipticCurves
    app_aead: CoseAlgorithms
    app_hash: CoseAlgorithms


class CipherSuite(Enum):
    _init_ = 'id config'
    _settings_ = MultiValue

    SUITE_0 = 0, skip(_CipherSetup(
        aead=CoseAlgorithms.AES_CCM_16_64_128,
        hash=CoseAlgorithms.SHA_256,
        dh_curve=CoseEllipticCurves.X25519,
        sign_alg=CoseAlgorithms.EDDSA,
        sign_curve=CoseEllipticCurves.ED25519,
        app_aead=CoseAlgorithms.AES_CCM_16_64_128,
        app_hash=CoseAlgorithms.SHA_256))

    SUITE_1 = 1, skip(_CipherSetup(
        aead=CoseAlgorithms.AES_CCM_16_128_128,
        hash=CoseAlgorithms.SHA_256,
        dh_curve=CoseEllipticCurves.X25519,
        sign_alg=CoseAlgorithms.EDDSA,
        sign_curve=CoseEllipticCurves.ED25519,
        app_aead=CoseAlgorithms.AES_CCM_16_64_128,
        app_hash=CoseAlgorithms.SHA_256))

    SUITE_2 = 2, skip(_CipherSetup(
        aead=CoseAlgorithms.AES_CCM_16_64_128,
        hash=CoseAlgorithms.SHA_256,
        dh_curve=CoseEllipticCurves.P_256,
        sign_alg=CoseAlgorithms.ES256,
        sign_curve=CoseEllipticCurves.P_256,
        app_aead=CoseAlgorithms.AES_CCM_16_64_128,
        app_hash=CoseAlgorithms.SHA_256))

    SUITE_3 = 3, skip(_CipherSetup(
        aead=CoseAlgorithms.AES_CCM_16_128_128,
        hash=CoseAlgorithms.SHA_256,
        dh_curve=CoseEllipticCurves.P_256,
        sign_alg=CoseAlgorithms.ES256,
        sign_curve=CoseEllipticCurves.P_256,
        app_aead=CoseAlgorithms.AES_CCM_16_64_128,
        app_hash=CoseAlgorithms.SHA_256))

    def __int__(self):
        return self.id

    @property
    def aead(self):
        return self.config.value.aead

    @property
    def hash(self):
        return self.config.value.hash

    @property
    def dh_curve(self):
        return self.config.value.dh_curve

    @property
    def sign_alg(self):
        return self.config.value.sign_alg

    @property
    def sign_curve(self):
        return self.config.value.sign_curve

    @property
    def app_aead(self):
        return self.config.value.app_aead

    @property
    def app_hash(self):
        return self.config.value.app_hash


@dataclass
class EdhocKDFInfo:
    edhoc_aead_id: int
    transcript_hash: bytes
    label: str
    length: int

    def encode(self) -> bytes:
        info = [int(self.edhoc_aead_id), self.transcript_hash, self.label, self.length]
        info = cbor2.dumps(info)
        return info
