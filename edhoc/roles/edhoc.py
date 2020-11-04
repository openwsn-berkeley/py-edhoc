from abc import ABCMeta
from typing import List

from cose import CoseEllipticCurves, CoseAlgorithms, KeyOps, OKP
from cose.keys.cosekey import CoseKey
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.x448 import X448PrivateKey

from edhoc.definitions import CipherSuite, Correlation


class EdhocRole(metaclass=ABCMeta):

    def __init__(self,
                 corr: Correlation,
                 conn_id: bytes,
                 cred_id_type,
                 cred: bytes,
                 supported_ciphers: List[CipherSuite]):
        self.corr = corr
        self.conn_id = conn_id
        self.supported_ciphers = supported_ciphers

        self.cred = cred
        self.cred_id_type = cred_id_type


