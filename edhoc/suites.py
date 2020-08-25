from enum import Enum, IntEnum
from typing import NamedTuple

from pycose.algorithms import AlgorithmIDs
from pycose.keys.cosekey import EllipticCurveType


class CipherSuite(NamedTuple):
    edhoc_aead_ciher: AlgorithmIDs
    edhoc_hash: AlgorithmIDs
    edhoc_ecdh_curve: EllipticCurveType
    edhoc_sign_alg: AlgorithmIDs
    edhoc_sign_curve: EllipticCurveType
    app_aead: AlgorithmIDs
    app_hash: AlgorithmIDs


class BaseCipherSuite(IntEnum):
    CIPHER_SUITE_0 = 0
    CIPHER_SUITE_1 = 1
    CIPHER_SUITE_2 = 2
    CIPHER_SUITE_3 = 3


class CipherSuiteMap(Enum):
    CIPHER_SUITE_0 = CipherSuite(
        edhoc_aead_ciher=AlgorithmIDs.AES_CCM_16_64_128,
        edhoc_hash=AlgorithmIDs.SHA_256,
        edhoc_ecdh_curve=EllipticCurveType.X25519,
        edhoc_sign_alg=AlgorithmIDs.EDDSA,
        edhoc_sign_curve=EllipticCurveType.ED25519,
        app_aead=AlgorithmIDs.AES_CCM_16_64_128,
        app_hash=AlgorithmIDs.SHA_256)

    CIPHER_SUITE_1 = CipherSuite(
        edhoc_aead_ciher=AlgorithmIDs.AES_CCM_16_128_128,
        edhoc_hash=AlgorithmIDs.SHA_256,
        edhoc_ecdh_curve=EllipticCurveType.X25519,
        edhoc_sign_alg=AlgorithmIDs.EDDSA,
        edhoc_sign_curve=EllipticCurveType.ED25519,
        app_aead=AlgorithmIDs.AES_CCM_16_64_128,
        app_hash=AlgorithmIDs.SHA_256)

    CIPHER_SUITE_2 = CipherSuite(
        edhoc_aead_ciher=AlgorithmIDs.AES_CCM_16_64_128,
        edhoc_hash=AlgorithmIDs.SHA_256,
        edhoc_ecdh_curve=EllipticCurveType.P_256,
        edhoc_sign_alg=AlgorithmIDs.ES256,
        edhoc_sign_curve=EllipticCurveType.P_256,
        app_aead=AlgorithmIDs.AES_CCM_16_64_128,
        app_hash=AlgorithmIDs.SHA_256)

    CIPHER_SUITE_3 = CipherSuite(
        edhoc_aead_ciher=AlgorithmIDs.AES_CCM_16_128_128,
        edhoc_hash=AlgorithmIDs.SHA_256,
        edhoc_ecdh_curve=EllipticCurveType.P_256,
        edhoc_sign_alg=AlgorithmIDs.ES256,
        edhoc_sign_curve=EllipticCurveType.P_256,
        app_aead=AlgorithmIDs.AES_CCM_16_64_128,
        app_hash=AlgorithmIDs.SHA_256)
