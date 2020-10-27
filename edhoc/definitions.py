from aenum import unique, IntEnum, NamedTuple, Enum
from cose import CoseAlgorithms, CoseEllipticCurves


@unique
class Method(IntEnum):
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
    SUITE_0 = 0, _CipherSetup(
        aead=CoseAlgorithms.AES_CCM_16_64_128,
        hash=CoseAlgorithms.SHA_256,
        dh_curve=CoseEllipticCurves.X25519,
        sign_alg=CoseAlgorithms.EDDSA,
        sign_curve=CoseEllipticCurves.ED25519,
        app_aead=CoseAlgorithms.AES_CCM_16_64_128,
        app_hash=CoseAlgorithms.SHA_256)

    SUITE_1 = 1, _CipherSetup(
        aead=CoseAlgorithms.AES_CCM_16_128_128,
        hash=CoseAlgorithms.SHA_256,
        dh_curve=CoseEllipticCurves.X25519,
        sign_alg=CoseAlgorithms.EDDSA,
        sign_curve=CoseEllipticCurves.ED25519,
        app_aead=CoseAlgorithms.AES_CCM_16_64_128,
        app_hash=CoseAlgorithms.SHA_256)

    SUITE_2 = 2, _CipherSetup(
        aead=CoseAlgorithms.AES_CCM_16_64_128,
        hash=CoseAlgorithms.SHA_256,
        dh_curve=CoseEllipticCurves.P_256,
        sign_alg=CoseAlgorithms.ES256,
        sign_curve=CoseEllipticCurves.P_256,
        app_aead=CoseAlgorithms.AES_CCM_16_64_128,
        app_hash=CoseAlgorithms.SHA_256)

    SUITE_3 = 3, _CipherSetup(
        aead=CoseAlgorithms.AES_CCM_16_128_128,
        hash=CoseAlgorithms.SHA_256,
        dh_curve=CoseEllipticCurves.P_256,
        sign_alg=CoseAlgorithms.ES256,
        sign_curve=CoseEllipticCurves.P_256,
        app_aead=CoseAlgorithms.AES_CCM_16_64_128,
        app_hash=CoseAlgorithms.SHA_256)
