import functools
from abc import ABCMeta, abstractmethod
from binascii import hexlify
from typing import List, Dict, Optional, Callable, Union, Any, Type, TYPE_CHECKING, Tuple

import cbor2
from cose import headers
from cose.curves import X25519, X448, P256
from cose.exceptions import CoseIllegalCurve
from cose.headers import CoseHeaderAttribute
from cose.keys import OKPKey, EC2Key, SymmetricKey
from cose.keys.keyops import EncryptOp
from cose.keys.keyparam import KpKeyOps, KpAlg
from cose.messages import Sign1Message, Enc0Message
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, hmac, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ec import SECP256R1
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.asymmetric.x448 import X448PublicKey, X448PrivateKey
from cryptography.hazmat.primitives.kdf.hkdf import HKDFExpand
from cryptography.x509 import Certificate

from edhoc.definitions import CipherSuite, Method, EdhocKDFInfo, Correlation, EdhocState
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
                 cred: Union[RPK, Certificate],
                 cred_id: CoseHeaderMap,
                 auth_key: RPK,
                 supported_ciphers: List[Type['CS']],
                 conn_id: bytes,
                 remote_cred_cb: Callable[[CoseHeaderMap], Union[Certificate, RPK]],
                 aad1_cb: Optional[Callable[..., bytes]],
                 aad2_cb: Optional[Callable[..., bytes]],
                 aad3_cb: Optional[Callable[..., bytes]],
                 ephemeral_key: Optional['CK'] = None):
        """
        Abstract base class for the EDHOC Responder and Initiator roles.

        :param cred: An RPK (Raw Public Key) or certificate
        :param cred_id: The credential identifier (a COSE header map)
        :param auth_key: The private authentication key (of type :class:`~cose.keys.ec2.EC2Key` or \
        :class:`~cose.keys.okp.OKPKey`). # noqa: E501
        :param supported_ciphers: A list of supported ciphers of type :class:`edhoc.definitions.CipherSuite`.
        :param conn_id: The connection identifier to be used.
        :param aad1_cb: A callback to pass received additional data to the application protocol.
        :param aad2_cb: A callback to pass additional data to the remote endpoint.
        :param aad3_cb: A callback to pass received additional data to the application protocol.
        :param ephemeral_key: Preload an (CoseKey) ephemeral key (if unset a random key will be generated).
        """

        self.cred, self._local_authkey = self._parse_credentials(cred)
        self.cred_id = cred_id
        self.auth_key = auth_key
        self.supported_ciphers = supported_ciphers

        self.remote_cred_cb = remote_cred_cb

        self._conn_id = conn_id
        self.aad1_cb = aad1_cb
        self.aad2_cb = aad2_cb
        self.aad3_cb = aad3_cb
        self.ephemeral_key = ephemeral_key

        # messages
        self.msg_1: Optional[MessageOne] = None
        self.msg_2: Optional[MessageTwo] = None
        self.msg_3: Optional[MessageThree] = None

        self._internal_state = EdhocState.EDHOC_WAIT

    @functools.lru_cache()
    def transcript(self, hash_func: Callable, hash_input: bytes) -> bytes:
        """ Compute the transcript hash. """

        transcript = hashes.Hash(hash_func())
        transcript.update(hash_input)
        return transcript.finalize()

    def _signature_or_mac(self, mac: bytes, transcript: bytes, aad_cb: Callable[..., bytes]) -> bytes:
        if not self.is_static_dh(self.role):
            cose_sign = Sign1Message(
                phdr=self.cred_id,
                uhdr={headers.Algorithm: self.cipher_suite.sign_alg},
                payload=mac,
                key=self.auth_key,
                external_aad=self._external_aad(self.cred, transcript, aad_cb))
            return cose_sign.compute_signature()
        else:
            return mac

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
        elif public_key.crv == X448:
            d = X448PrivateKey.from_private_bytes(private_key.d)

            x = X448PublicKey.from_public_bytes(public_key.x)
        elif public_key.crv == P256:
            d = ec.derive_private_key(int(hexlify(private_key.d), 16), SECP256R1(), default_backend())

            x = ec.EllipticCurvePublicNumbers(int(hexlify(public_key.x), 16),
                                              int(hexlify(public_key.y), 16),
                                              SECP256R1())
        else:
            raise CoseIllegalCurve(f"{public_key.crv} is unsupported")

        secret = d.exchange(x)
        return secret

    @property
    def edhoc_state(self):
        return self._internal_state

    def exporter(self, label: str, length: int):
        return self._hkdf_expand(length, label, self._prk4x3m, self._th4_input)

    @property
    @abstractmethod
    def corr(self) -> Correlation:
        """ Returns the correlation value for the EDHOC transport protocol. """

        raise NotImplementedError()

    @property
    @abstractmethod
    def method(self) -> Method:
        """ Returns the EDHOC method type. """

        raise NotImplementedError()

    @property
    @abstractmethod
    def conn_idi(self) -> bytes:
        """ Returns the Initiator's connection identifier if required by the correlation value, otherwise an empty
        byte string. """

        raise NotImplementedError()

    @property
    @abstractmethod
    def conn_idr(self) -> bytes:
        """ Returns the Responder's connection identifier if required by the correlation value, otherwise an empty
        byte string. """

        raise NotImplementedError()

    @property
    @abstractmethod
    def cred_idi(self) -> CoseHeaderMap:
        """ The credential identifier for the Initiator. """

        raise NotImplementedError()

    @property
    @abstractmethod
    def cred_idr(self) -> CoseHeaderMap:
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

        if self.conn_idr == b'':
            return self.conn_idr
        else:
            return cbor2.dumps(EdhocMessage.encode_bstr_id(self.conn_idr))

    @property
    def data_2(self) -> CBOR:
        """ Create the data_2 message part from EDHOC message 2. """

        return MessageTwo.data_2(self.g_y, self.conn_idr, self.corr, self.conn_idi)

    @property
    def _th2_input(self) -> CBOR:
        return b''.join([self.msg_1.encode(self.corr), self.data_2])

    @property
    def _th3_input(self) -> CBOR:
        input_th = [self.transcript(self.cipher_suite.hash.hash_cls, self._th2_input), self.msg_2.ciphertext]
        return b''.join([cbor2.dumps(part) for part in input_th] + [self.data_3])

    @property
    def _th4_input(self) -> CBOR:
        input_th = [self.transcript(self.cipher_suite.hash.hash_cls, self._th3_input), self.msg_3.ciphertext]
        return b''.join([cbor2.dumps(part) for part in input_th])

    @property
    @functools.lru_cache()
    def _prk2e(self) -> bytes:
        return self._prk(self.ephemeral_key, self.remote_pubkey, b'')

    @property
    def _prk3e2m(self) -> bytes:
        if not self.is_static_dh('R'):
            return self._prk2e
        else:
            return self._prk3e2m_static_dh(self._prk2e)

    @property
    def _prk4x3m(self) -> bytes:
        if not self.is_static_dh('I'):
            return self._prk3e2m
        else:
            return self._prk4x3m_static_dh(self._prk3e2m)

    def _prk(self, private_key: Union[RPK, 'CK'], pub_key: Union[RPK, 'CK'], salt: bytes) -> bytes:
        secret = self.shared_secret(private_key, pub_key)

        prk_2e = hmac.HMAC(algorithm=self.cipher_suite.hash.hash_cls(), key=salt)
        prk_2e.update(secret)

        prk = prk_2e.finalize()
        return prk

    @property
    @abstractmethod
    def _hkdf2(self) -> Callable:
        raise NotImplementedError()

    @property
    @abstractmethod
    def _hkdf3(self) -> Callable:
        raise NotImplementedError()

    @abstractmethod
    def _prk3e2m_static_dh(self, prk: bytes):
        raise NotImplementedError()

    @abstractmethod
    def _prk4x3m_static_dh(self, prk: bytes):
        raise NotImplementedError()

    def _mac(self,
             cred_id: CoseHeaderMap,
             cred,
             hkdf: Callable,
             key_label: str,
             key_len: int,
             iv_label: str,
             iv_len: int,
             th_input: bytes,
             prk: bytes,
             aad_cb: Callable[..., bytes]) -> bytes:

        iv_bytes = hkdf(iv_len, iv_label, prk)
        cose_key = self._create_cose_key(hkdf, key_len, key_label, prk, [EncryptOp])

        # calculate the mac using a COSE_Encrypt0 message
        return Enc0Message(
            phdr=cred_id,
            uhdr={headers.IV: iv_bytes, headers.Algorithm: self.cipher_suite.aead},
            payload=b'',
            key=cose_key,
            external_aad=self._external_aad(cred, th_input, aad_cb)
        ).encrypt()

    def _create_cose_key(self, hkdf, key_len: int, label: str, prk: bytes, ops: List[Type['KEYOPS']]) -> SymmetricKey:
        return SymmetricKey(
            k=hkdf(key_len, label, prk),
            optional_params={KpKeyOps: ops, KpAlg: self.cipher_suite.aead}
        )

    def _external_aad(self, cred: Union[Certificate, RPK], transcript: bytes, aad_cb: Callable[..., bytes]) -> CBOR:
        """Build an unserialized external AAD out of a transcript hash, a cred
        and AAD data.

        As its format is shared among messages, the cred needs to be picked
        suitably for the message (CRED_R in message 2, CRED_I in message 3);
        depending on whether this is used in a creating or a verifying
        capacity, self.cred or self.remote_cred needs to be passed in.
        """
        if isinstance(cred, OKPKey) or isinstance(cred, EC2Key):
            encoded_credential = cred.encode()
        elif isinstance(cred, Certificate):
            encoded_credential = cbor2.dumps(cred.tbs_certificate_bytes)
        else:
            # TODO: this shouldn't be here, but since somes of the test vectors are not real certificates we need
            #  this hack
            encoded_credential = cbor2.dumps(cred)

        aad = [cbor2.dumps(self.transcript(self.cipher_suite.hash.hash_cls, transcript)), encoded_credential]

        if aad_cb is not None:
            ad = aad_cb()

            if ad != b'':
                aad.append(ad)

        aad = b"".join(aad)
        return aad

    @abstractmethod
    def _decrypt(self, ciphertext: bytes) -> bool:
        raise NotImplementedError()

    @functools.lru_cache()
    def _hkdf_expand(self, length: int, label: str, prk: bytes, transcript: bytes) -> bytes:
        """
        Derive the encryption key and the IV to protect the COSE_Encrypt0 message in the EDHOC message 2.

        :return:
        """
        hash_func = self.cipher_suite.hash.hash_cls

        info = EdhocKDFInfo(
            edhoc_aead_id=self.cipher_suite.aead.identifier,
            transcript_hash=self.transcript(hash_func, transcript),
            label=label,
            length=length)

        derived_bytes = HKDFExpand(
            algorithm=hash_func(),
            length=info.length,
            info=info.encode()).derive(prk)

        return derived_bytes

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

    @classmethod
    def _custom_cbor_encoder(cls, encoder, cose_attribute: 'CoseHeaderAttribute'):
        encoder.encode(cose_attribute.identifier)

    def _populate_remote_details(self, remote_cred_id):
        self.remote_cred, self.remote_authkey = self._parse_credentials(self.remote_cred_cb(remote_cred_id))
