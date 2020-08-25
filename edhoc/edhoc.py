from abc import ABCMeta, abstractmethod
from typing import Optional, Union, Callable, List

from cryptography.hazmat.backends import openssl
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.hashes import SHA256, Hash
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, NoEncryption, PublicFormat

from edhoc.suites import BaseCipherSuite, CipherSuiteMap
from pycose.algorithms import AlgorithmIDs
from pycose.keys.cosekey import EllipticCurveType
from pycose.keys.ec import EC2
from pycose.keys.okp import OKP


class EdhocRole(metaclass=ABCMeta):
    CURVE_MAPPING = {
        EllipticCurveType.X25519: x25519.X25519PrivateKey
    }

    HASH_MAPPING = {
        AlgorithmIDs.SHA_256: SHA256
    }

    def __init__(self,
                 method_corr: Optional[int] = None,
                 conn_idi: bytes = b'',
                 conn_idr: bytes = b'',
                 cipher_suite: Optional[BaseCipherSuite] = None,
                 aad1: bytes = b'',
                 aad2: bytes = b'',
                 aad3: bytes = b''):
        self.method_corr = method_corr
        self.conn_idi = conn_idi
        self.conn_idr = conn_idr
        self.cipher_suite = cipher_suite

        self.aad1 = aad1
        self.aad2 = aad2
        self.aad3 = aad3

        self.callback_msg1: Optional[Callable] = None
        self.callback_msg2: Optional[Callable] = None
        self.callback_msg3: Optional[Callable] = None

        self.priv_key: Optional[Union[EC2, OKP]] = None
        self.pub_key: Optional[Union[EC2, OKP]] = None

    @property
    def callback_msg1(self) -> Callable[[], bytes]:
        return self._callback_msg1

    @callback_msg1.setter
    def callback_msg1(self, func: Callable[[], bytes]):
        self._callback_msg1 = func

    @property
    def callback_msg2(self) -> Callable[[], bytes]:
        return self._callback_msg2

    @callback_msg2.setter
    def callback_msg2(self, func: Callable[[], bytes]) -> None:
        self._callback_msg2 = func

    @property
    def callback_msg3(self) -> Callable[[], bytes]:
        return self._callback_msg3

    @callback_msg3.setter
    def callback_msg3(self, func: Callable[[], bytes]) -> None:
        self._callback_msg3 = func

    def _compute_transcript(self, msg_parts: List[bytes]):
        """ Computes the transcript hash """

        hash_func_id = CipherSuiteMap[BaseCipherSuite(self.cipher_suite).name].value.edhoc_hash
        hash_func = self.HASH_MAPPING[hash_func_id]

        h = Hash(algorithm=hash_func(), backend=openssl.backend)

        for part in msg_parts:
            h.update(part)

        return h.finalize()

    def _compute_ecdh(self) -> bytes:
        curve = CipherSuiteMap[BaseCipherSuite(self.cipher_suite).name].value.edhoc_ecdh_curve

        if isinstance(self.priv_key, OKP) and isinstance(self.pub_key, OKP) and curve == EllipticCurveType.X25519:
            private_key = x25519.X25519PrivateKey.from_private_bytes(data=self.priv_key.d)
            public_key = x25519.X25519PublicKey.from_public_bytes(data=self.pub_key.x)

            return private_key.exchange(public_key)
        elif isinstance(self.priv_key, OKP) and isinstance(self.pub_key, OKP) and curve == EllipticCurveType.P_256:
            pass
        else:
            TypeError("Invalid key or curve type")

    def _key_derivation(self, key: bytes, length=16, salt=b'', info=b''):
        hash_func_id = CipherSuiteMap[BaseCipherSuite(self.cipher_suite).name].value.edhoc_hash
        hash_func = self.HASH_MAPPING[hash_func_id]

        hkdf = HKDF(algorithm=hash_func(),
                    length=length,
                    salt=salt,
                    info=info,
                    backend=openssl.backend)
        return hkdf.derive(key)

    def _gen_ephemeral_key(self, curve: EllipticCurveType):
        """ Generate an ephemeral key pair to perform the ECDH computation. """

        private_key = self.CURVE_MAPPING[curve]
        private_key = private_key.generate()

        d_bytes = private_key.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())

        x_bytes = private_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)

        return OKP(d=d_bytes, x=x_bytes)


class EdhocMessage(metaclass=ABCMeta):
    @classmethod
    @abstractmethod
    def decode(cls, received: bytes):
        raise NotImplementedError

    @abstractmethod
    def encode(self):
        raise NotImplementedError
