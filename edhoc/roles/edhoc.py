import functools
from abc import ABCMeta, abstractmethod
from binascii import hexlify
from typing import List, Dict, Optional, Callable, Union, Any, Tuple

import cbor2
from cose import EC2, OKP, CoseEllipticCurves, Sign1Message, KeyOps, SymmetricKey, Enc0Message
from cose.attributes.algorithms import config as config_cose, CoseAlgorithms
from cose.exceptions import CoseIllegalCurve
from cose.keys.cosekey import CoseKey
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.asymmetric.x448 import X448PublicKey, X448PrivateKey
from cryptography.hazmat.primitives.kdf.hkdf import HKDFExpand

from edhoc.definitions import CipherSuite, Method, EdhocKDFInfo, Correlation, EdhocState
from edhoc.messages import MessageOne, MessageTwo, MessageThree, EdhocMessage

Key = Union[EC2, OKP]
CBOR = bytes
CoseHeaderMap = Dict[int, Any]


class EdhocRole(metaclass=ABCMeta):

    def __init__(self,
                 cred: CBOR,
                 cred_id: CoseHeaderMap,
                 auth_key: Key,
                 supported_ciphers: List[CipherSuite],
                 conn_id: bytes,
                 peer_cred: Optional[Union[Callable[..., CBOR], CBOR]],
                 aad1_cb: Optional[Callable[..., bytes]],
                 aad2_cb: Optional[Callable[..., bytes]],
                 aad3_cb: Optional[Callable[..., bytes]],
                 ephemeral_key: Optional[Key] = None):
        """
        Abstract base class for the EDHOC Responder and Initiator roles.

        :param cred: CBOR-encoded public authentication credentials.
        :param cred_id: The credential identifier (a CBOR encoded COSE header map)
        :param auth_key: The private authentication key (of type :class:`~cose.keys.ec2.EC2` or \
        :class:`~cose.keys.okp.OKP`). Forms a key pair with `local_authkey`. # noqa: E501
        :param supported_ciphers: A list of ciphers supported.
        :param conn_id: The connection identifier to be used.
        :param aad1_cb: A callback to pass received additional data to the application protocol.
        :param aad2_cb: A callback to pass additional data to the remote endpoint.
        :param aad3_cb: A callback to pass received additional data to the application protocol.
        :param ephemeral_key: Preload an (CoseKey) ephemeral key (if unset a random key will be generated).
        """

        self.cred, self._local_authkey = self._parse_credentials(cred)
        self.cred_id = cred_id
        self.auth_key = auth_key
        self.supported_ciphers = [c for c in map(int, supported_ciphers)]
        self._peer_cred, self._remote_authkey = self._parse_credentials(peer_cred)
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

        transcript = hashes.Hash(hash_func(), backend=default_backend())
        transcript.update(hash_input)
        return transcript.finalize()

    def _signature_or_mac(self, mac: bytes, transcript: bytes, aad_cb: Callable[..., bytes]) -> bytes:

        role = 'I' if type(self).__name__ == 'Initiator' else 'R'

        if not self.is_static_dh(role):
            cose_sign = Sign1Message(
                phdr=self.cred_id,
                payload=mac,
                external_aad=self._external_aad(transcript, aad_cb))
            return cose_sign.compute_signature(self.auth_key)
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
    def shared_secret(private_key: Key, public_key: Key) -> bytes:
        """ Compute the shared secret. """

        if public_key.crv == CoseEllipticCurves.X25519:
            d = X25519PrivateKey.from_private_bytes(private_key.d)
            x = X25519PublicKey.from_public_bytes(public_key.x)
        elif public_key.crv == CoseEllipticCurves.X448:
            d = X448PrivateKey.from_private_bytes(private_key.d)
            x = X448PublicKey.from_public_bytes(public_key.x)
        elif public_key.crv == CoseEllipticCurves.P_256:
            d = ec.derive_private_key(
                int(hexlify(private_key.d), 16),
                config_cose(public_key.crv).curve[1](),
                default_backend())

            x = ec.EllipticCurvePublicNumbers(
                int(hexlify(public_key.x), 16),
                int(hexlify(public_key.y), 16),
                config_cose(public_key.crv).curve[1]())
        else:
            raise CoseIllegalCurve(f"{public_key.crv} is unsupported")

        secret = d.exchange(x)
        return secret

    @property
    def edhoc_state(self):
        return self._internal_state

    def exporter(self, label: str, length: int):
        hash_func = config_cose(self.cipher_suite.hash).hash
        return self._hkdf_expand(length, label, self._prk4x3m, self.transcript(hash_func, self._th4_input))

    @property
    @abstractmethod
    def peer_cred(self):
        """ Returns the peer's credentials, e.g. certificate. """

        raise NotImplementedError()

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
    def remote_pubkey(self) -> Key:
        """ Returns the remote ephemeral public key. """

        raise NotImplementedError()

    @property
    @abstractmethod
    def local_pubkey(self) -> Key:
        """ Returns the local ephemeral public key. """

        raise NotImplementedError()

    @property
    @abstractmethod
    def remote_authkey(self) -> Key:
        """ The remote public authentication key. """

        raise NotImplementedError()

    @property
    @abstractmethod
    def local_authkey(self) -> Key:
        """ The local public authentication key. """

        raise NotImplementedError()

    @property
    @abstractmethod
    def cipher_suite(self) -> CipherSuite:
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

        return MessageTwo.data_2(self.g_y, self.conn_idr, self.conn_idi)

    @property
    def _th2_input(self) -> CBOR:
        return b''.join([self.msg_1.encode(), self.data_2])

    @property
    def _th3_input(self) -> CBOR:
        hash_func = config_cose(self.cipher_suite.hash).hash

        input_th = [self.transcript(hash_func, self._th2_input), self.msg_2.ciphertext]
        return b''.join([cbor2.dumps(part) for part in input_th] + [self.data_3])

    @property
    def _th4_input(self) -> CBOR:
        hash_func = config_cose(self.cipher_suite.hash).hash

        input_th = [self.transcript(hash_func, self._th3_input), self.msg_3.ciphertext]
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

    def _prk(self, private_key: Key, pub_key: Key, salt: bytes) -> bytes:
        h = self.cipher_suite.hash
        secret = self.shared_secret(private_key, pub_key)

        prk_2e = hmac.HMAC(algorithm=config_cose(h).hash(), key=salt, backend=default_backend())
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
             hkdf: Callable,
             key_label: str,
             key_len: int,
             iv_label: str,
             iv_len: int,
             th_input: bytes,
             prk: bytes,
             aad_cb: Callable[..., bytes]) -> bytes:

        iv_bytes = hkdf(iv_len, iv_label, prk)
        cose_key = self._create_cose_key(hkdf, key_len, key_label, prk, KeyOps.ENCRYPT)

        # calculate the mac using a COSE_Encrypt0 message
        return Enc0Message(
            phdr=self.cred_id,
            payload=b'',
            external_aad=self._external_aad(th_input, aad_cb)
        ).encrypt(nonce=iv_bytes, key=cose_key)

    def _create_cose_key(self, hkdf, key_len: int, label: str, prk: bytes, ops: KeyOps) -> SymmetricKey:
        return SymmetricKey(
            k=hkdf(key_len, label, prk),
            key_ops=ops,
            alg=self.cipher_suite.aead)

    def _external_aad(self, transcript: bytes, aad_cb: Callable[..., bytes]) -> CBOR:
        hash_func = config_cose(self.cipher_suite.hash).hash

        aad = [cbor2.dumps(self.transcript(hash_func, transcript)), self.cred]

        if aad_cb is not None:
            ad = aad_cb()

            if ad != b'':
                aad.append(ad)

        aad = b"".join(aad)
        return aad

    def _verify_signature(self, signature: bytes) -> bool:
        _ = signature

        if self.peer_cred is None:
            return True
        else:
            # TODO: needs valid CBOR certificate decoding
            return True

    @abstractmethod
    def _decrypt(self, ciphertext: bytes) -> bool:
        raise NotImplementedError()

    @functools.lru_cache()
    def _hkdf_expand(self, length: int, label: str, prk: bytes, transcript: bytes) -> bytes:
        """
        Derive the encryption key and the IV to protect the COSE_Encrypt0 message in the EDHOC message 2.

        :return:
        """
        hash_func = config_cose(self.cipher_suite.hash).hash

        info = EdhocKDFInfo(
            edhoc_aead_id=self.cipher_suite.aead,
            transcript_hash=self.transcript(hash_func, transcript),
            label=label,
            length=length)

        derived_bytes = HKDFExpand(
            algorithm=hash_func(),
            length=info.length,
            info=info.encode(),
            backend=default_backend()).derive(prk)

        return derived_bytes

    def _generate_ephemeral_key(self) -> None:
        """
        Generate a new ephemeral key if the key was not already set.

        :return: None
        """

        if self.ephemeral_key is not None:
            return

        chosen_suite = CipherSuite(self.cipher_suite)

        if chosen_suite.dh_curve in [CoseEllipticCurves.X25519, CoseEllipticCurves.X448]:
            self.ephemeral_key = OKP.generate_key(CoseAlgorithms.DIRECT, curve_type=chosen_suite.dh_curve,
                                                  key_ops=KeyOps.SIGN)
        else:
            self.ephemeral_key = EC2.generate_key(CoseAlgorithms.DIRECT, curve_type=chosen_suite.dh_curve,
                                                  key_ops=KeyOps.SIGN)

    @staticmethod
    def _parse_credentials(cred: Union[CBOR, Callable]) -> Tuple[Union[CBOR, Callable], Union[Key, Callable]]:
        if isinstance(cred, bytes):

            if isinstance(cbor2.loads(cred), dict):
                # this is an RPK
                cose_key = CoseKey.decode(cbor2.loads(cred))
                return cred, cose_key

            else:
                # TODO: update when test vectors for CBOR encoded certificates are correct
                return cred, None
        else:

            return cred, cred
