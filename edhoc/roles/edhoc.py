import functools
from abc import ABCMeta, abstractmethod
from binascii import hexlify
from typing import List, Dict, Optional, Callable, Union, Any, Type, TYPE_CHECKING, Tuple

import cbor2
import cose
from cose import headers
from cose.keys.curves import X25519, X448, P256, P384
from cose.exceptions import CoseUnsupportedCurve
from cose.headers import CoseHeaderAttribute
from cose.keys import OKPKey, EC2Key, SymmetricKey
from cose.keys.keyops import EncryptOp
from cose.keys.keyparam import KpKeyOps, KpAlg
from cose.messages import Sign1Message, Enc0Message
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, hmac, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.asymmetric.x448 import X448PublicKey, X448PrivateKey
from cryptography.hazmat.primitives.kdf.hkdf import HKDFExpand, HKDF
from cryptography.x509 import Certificate

from edhoc.definitions import CipherSuite, Method, EdhocKDFInfo, Correlation, EdhocState, cborstream
from edhoc.exceptions import EdhocException
from edhoc.messages import MessageOne, MessageTwo, MessageThree, EdhocMessage

if TYPE_CHECKING:
    from edhoc.definitions import CS
    from cose.keys.keyops import KEYOPS
    from cose.keys.cosekey import CK
    from cose.headers import CoseHeaderAttribute

RPK = Union[EC2Key, OKPKey]
CBOR = bytes
CoseHeaderMap = Dict[Type[CoseHeaderAttribute], Any]

class EdhocRole(metaclass=ABCMeta):

    def __init__(self,
                 cred_local: Union[RPK, Certificate],
                 id_cred_local: CoseHeaderMap,
                 auth_key: RPK,
                 supported_ciphers: List[Type['CS']],
                 c_local: Union[bytes, int],
                 remote_cred_cb: Callable[[CoseHeaderMap], Union[Certificate, RPK]],
                 aad1_cb: Optional[Callable[..., bytes]],
                 aad2_cb: Optional[Callable[..., bytes]],
                 aad3_cb: Optional[Callable[..., bytes]],
                 ephemeral_key: Optional['CK'] = None):
        """
        Abstract base class for the EDHOC Responder and Initiator roles.

        :param cred_local: An RPK (Raw Public Key) or certificate
        :param id_cred_local: The credential identifier (a COSE header map)
        :param auth_key: The private authentication key (of type :class:`~cose.keys.ec2.EC2Key` or \
        :class:`~cose.keys.okp.OKPKey`). # noqa: E501
        :param supported_ciphers: A list of supported ciphers of type :class:`edhoc.definitions.CipherSuite`.
        :param c_local: The connection identifier to be used.
        :param aad1_cb: A callback to pass received additional data to the application protocol.
        :param aad2_cb: A callback to pass additional data to the remote endpoint.
        :param aad3_cb: A callback to pass received additional data to the application protocol.
        :param ephemeral_key: Preload an (CoseKey) ephemeral key (if unset a random key will be generated).
        """

        self.cred_local, self._local_authkey = self._parse_credentials(cred_local)
        self.id_cred_local = id_cred_local
        self.auth_key = auth_key
        self.supported_ciphers = supported_ciphers

        self.remote_cred_cb = remote_cred_cb

        self._c_local = c_local
        self.aad1_cb = aad1_cb
        self.aad2_cb = aad2_cb
        self.aad3_cb = aad3_cb
        self.ephemeral_key = ephemeral_key

        # messages
        self.msg_1: Optional[MessageOne] = None
        self.msg_2: Optional[MessageTwo] = None
        self.msg_3: Optional[MessageThree] = None

        self._internal_state = EdhocState.EDHOC_WAIT

    # FIXME deduplciate against transcript
    def hash(self, data):
        """Apply the H() function of the EDHOC specification, based on the
        selections previously taken"""
        h = hashes.Hash(self.cipher_suite.hash.hash_cls())
        h.update(data)
        return h.finalize()

    def is_static_dh(self, role: str) -> bool:
        """
        Check if EDHOC role uses static DH authentication.

        :param role: Check if Initiator 'I' or Responder 'R' uses static Diffie-Hellman keys for authentication.
        :return: Boolean value, True if EDHOC role uses static Diffie-Hellman keys for authentication else False.
        """
        if role not in {'I', 'R'}:
            raise ValueError("role should be either 'I' (initiator) or 'R' (responder)")

        if role == 'I':
            return self.method in {Method.STATIC_SIGN, Method.STATIC_STATIC}
        else:
            return self.method in {Method.SIGN_STATIC, Method.STATIC_STATIC}

    # @functools.lru_cache()
    @staticmethod
    def shared_secret(private_key: 'CK', public_key: 'CK') -> bytes:
        """ Compute the shared secret. """

        if public_key.crv == X25519:
            d = X25519PrivateKey.from_private_bytes(private_key.d)
            x = X25519PublicKey.from_public_bytes(public_key.x)
            secret = d.exchange(x)
        elif public_key.crv == X448:
            d = X448PrivateKey.from_private_bytes(private_key.d)

            x = X448PublicKey.from_public_bytes(public_key.x)
            secret = d.exchange(x)
        elif public_key.crv in (P256, P384):
            curve_obj = public_key.crv.curve_obj()
            d = ec.derive_private_key(int(hexlify(private_key.d), 16), curve_obj, default_backend())

            x = ec.EllipticCurvePublicNumbers(int(hexlify(public_key.x), 16),
                                              int(hexlify(public_key.y), 16),
                                              curve_obj)
            x = x.public_key()
            secret = d.exchange(ec.ECDH(), x)
        else:
            raise CoseUnsupportedCurve(f"{public_key.crv} is unsupported")

        return secret

    @property
    def shared_secret_xy(self):
        return self.shared_secret(self.ephemeral_key, self.remote_pubkey)

    @property
    @abstractmethod
    def shared_secret_rx(self):
        raise NotImplementedError()

    @property
    @abstractmethod
    def shared_secret_iy(self):
        raise NotImplementedError()

    @property
    def edhoc_state(self):
        return self._internal_state

    def exporter(self, label: str, context: bytes, length: int):
        return self.edhoc_kdf(self.prk_4x3m, self.th_4, label, context, length)

    @property
    @abstractmethod
    def method(self) -> Method:
        """ Returns the EDHOC method type. """

        raise NotImplementedError()

    @property
    @abstractmethod
    def c_i(self) -> bytes:
        """ Returns the Initiator's connection identifier if required by the correlation value, otherwise an empty
        byte string. """

        raise NotImplementedError()

    @property
    @abstractmethod
    def c_r(self) -> bytes:
        """ Returns the Responder's connection identifier if required by the correlation value, otherwise an empty
        byte string. """

        raise NotImplementedError()

    @property
    def c_r(self) -> bytes:
        # rename to current identifiers
        return self.c_r

    @property
    @abstractmethod
    def id_cred_i(self) -> CoseHeaderMap:
        """ The credential identifier for the Initiator. """

        raise NotImplementedError()

    @property
    @abstractmethod
    def id_cred_r(self) -> CoseHeaderMap:
        """ The credential identifier for the Responder. """

        raise NotImplementedError()

    @property
    @abstractmethod
    def g_y(self) -> bytes:
        """ The Responder's ephemeral public key in raw bytes. """

        raise NotImplementedError()

    @property
    @abstractmethod
    def g_x(self) -> bytes:
        """ The Initiator's ephemeral public key in raw bytes. """

        raise NotImplementedError()

    @property
    @abstractmethod
    def remote_pubkey(self) -> RPK:
        """ Returns the remote ephemeral public key. """

        raise NotImplementedError()

    @property
    @abstractmethod
    def local_pubkey(self) -> RPK:
        """ Returns the local ephemeral public key. """

        raise NotImplementedError()

    @property
    @abstractmethod
    def local_authkey(self) -> RPK:
        """ The local public authentication key. """

        raise NotImplementedError()

    @property
    @abstractmethod
    def cipher_suite(self) -> 'CS':
        raise NotImplementedError()

    @property
    def data_3(self) -> CBOR:
        """ Create the data_3 message part from EDHOC message 3. """

        return cbor2.dumps(self.c_r)

    @property
    def _th2_input(self) -> CBOR:
        # FIXME once this is used we can probably do away with msg_1 entirely
        msg_1_hash = self.hash(self.msg_1.encoded)
        input_data = [msg_1_hash, self.g_y, self.c_r]
        return b''.join(cbor2.dumps(i) for i in input_data)

    def extract(self, salt, ikm):
        # FIXME: Comprehensively enumerate SHA-2 algorithms, or define a property there
        if self.cipher_suite.hash in (cose.algorithms.Sha256, cose.algorithms.Sha384):
            result = hmac.HMAC(algorithm=self.cipher_suite.hash.hash_cls(), key=salt)
            result.update(ikm)
            return result.finalize()
        else:
            raise NotImplementedError()

    @property
    def prk_2e(self):
        return self.extract(b"", self.shared_secret_xy)

    @property
    def prk_3e2m(self):
        if self.is_static_dh('R'):
            return self.extract(self.prk_2e, self.shared_secret_rx)
        else:
            return self.prk_2e

    @property
    def prk_4x3m(self):
        if self.is_static_dh('I'):
            return self.extract(self.prk_3e2m, self.shared_secret_iy)
        else:
            return self.prk_3e2m

    @property
    def th_2(self) -> bytes:
        return self.hash(self._th2_input)

    @property
    def mac_length_2(self) -> int:
        if self.is_static_dh('R'):
            return self.cipher_suite.edhoc_mac_length
        else:
            return self.cipher_suite.hash.hash_cls.digest_size

    @property
    def mac_length_3(self) -> int:
        if self.is_static_dh('I'):
            return self.cipher_suite.edhoc_mac_length
        else:
            return self.cipher_suite.hash.hash_cls.digest_size

    @property
    def mac_2(self) -> bytes:
        # FIXME
        ead_2 = []
        return self.edhoc_kdf(
                self.prk_3e2m,
                self.th_2,
                "MAC_2",
                cborstream([self.id_cred_r, self.cred_r, *ead_2]),
                self.mac_length_2,
                )

    @property
    def mac_3(self) -> bytes:
        # FIXME
        ead_3 = []
        return self.edhoc_kdf(
                self.prk_4x3m,
                self.th_3,
                "MAC_3",
                cborstream([self.id_cred_i, self.cred_i, *ead_3]),
                self.mac_length_3,
                )

    @property
    def th_3(self) -> bytes:
        th_2 = self.th_2
        ciphertext_2 = self.ciphertext_2
        return self.hash(cborstream([th_2, ciphertext_2]))

    @property
    def th_4(self) -> bytes:
        return self.hash(cborstream([self.th_3, self.ciphertext_3]))

    # FIXME reevaluate where we want to do these
    @functools.lru_cache()
    def edhoc_kdf(self, prk: bytes, transcript_hash: bytes, label: str, context: bytes, length: int) -> bytes:
        """Implementation of EDHOC-KDF() of the specification"""

        # FIXME: This is duplicating _hkdf_expand, and expanding the info
        # changes right in place. Remove them once this is done.

        hash_func = self.cipher_suite.hash.hash_cls

        info = EdhocKDFInfo(
                transcript_hash=transcript_hash,
                label=label,
                context=context,
                length=length,
                )

        return HKDFExpand(
            algorithm=hash_func(),
            length=info.length,
            info=info.encode()).derive(prk)

    def _generate_ephemeral_key(self) -> None:
        """
        Generate a new ephemeral key if the key was not already set.

        :return: None
        """

        if self.ephemeral_key is not None:
            return

        chosen_suite = CipherSuite.from_id(self.cipher_suite)

        if chosen_suite.dh_curve in [X25519, X448]:
            self.ephemeral_key = OKPKey.generate_key(crv=chosen_suite.dh_curve)
        else:
            self.ephemeral_key = EC2Key.generate_key(crv=chosen_suite.dh_curve)

    @staticmethod
    def _parse_credentials(cred: Union[RPK, 'Certificate']) -> Tuple[Union[Certificate, RPK], RPK]:
        """
        Internal helper function that parser credentials and extracts the public key.
        """
        if isinstance(cred, EC2Key) or isinstance(cred, OKPKey):
            cred, auth_key = cred, cred
        elif isinstance(cred, Certificate):
            cred, auth_key = cred, cred.public_key().public_bytes(serialization.Encoding.Raw,
                                                                  serialization.PublicFormat.Raw)
        elif isinstance(cred, tuple):
            cred, auth_key = cred
        else:
            raise EdhocException("Invalid credentials")

        return cred, auth_key

    def _populate_remote_details(self, remote_cred_id):
        self.remote_cred, self.remote_authkey = self._parse_credentials(self.remote_cred_cb(remote_cred_id))

    @property
    @abstractmethod
    def cred_i(self):
        raise NotImplementedError()

    @property
    @abstractmethod
    def cred_r(self):
        raise NotImplementedError()
