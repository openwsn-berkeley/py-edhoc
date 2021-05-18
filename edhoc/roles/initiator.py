import functools
import os
from typing import List, Optional, Callable, Union, Tuple, TYPE_CHECKING, Type

import cbor2
from asn1crypto.x509 import Certificate
from cose import headers
from cose.curves import X448, X25519
from cose.headers import KID
from cose.keys import OKPKey
from cose.keys.keyops import EncryptOp
from cose.messages import Enc0Message, Sign1Message

from edhoc.definitions import CipherSuite, Method, Correlation, EdhocState
from edhoc.messages import MessageOne, MessageTwo, MessageThree, EdhocMessage, MessageError
from edhoc.roles.edhoc import EdhocRole, CoseHeaderMap, RPK

if TYPE_CHECKING:
    from edhoc.definitions import CS
    from cose.keys.cosekey import CK


class Initiator(EdhocRole):
    role = 'I'
    remote_role = 'R'

    def __init__(self,
                 corr: Correlation,
                 method: Method,
                 cred: Union[RPK, Certificate],
                 cred_idi: CoseHeaderMap,
                 auth_key: RPK,
                 selected_cipher: Type['CS'],
                 supported_ciphers: List[Type['CS']],
                 remote_cred_cb:  Callable[[CoseHeaderMap], Union[Certificate, RPK]],
                 conn_idi: Optional[bytes] = None,
                 aad1_cb: Optional[Callable[..., bytes]] = None,
                 aad2_cb: Optional[Callable[..., bytes]] = None,
                 aad3_cb: Optional[Callable[..., bytes]] = None,
                 ephemeral_key: Optional['CK'] = None):
        """
        Create an EDHOC Initiator.

        :param corr: Correlation value (depends on the transport protocol).
        :param method: EDHOC method type (signatures, static DH or a mix).
        :param cred: The public authentication credentials of the Initiator.
        :param cred_idi: The Initiator's credential identifier (a CBOR encoded COSE header map)
        :param auth_key: The private authentication key (CoseKey) of the Responder.
        :param selected_cipher: Provide the selected cipher.
        :param supported_ciphers: A list of ciphers supported by the Responder.
        :param conn_idi: The connection identifier to be used
        :param remote_cred_cb: A callback that fetches the remote credentials.
        :param aad1_cb: A callback to pass received additional data to the application protocol.
        :param aad2_cb: A callback to pass additional data to the remote endpoint.
        :param aad3_cb: A callback to pass received additional data to the application protocol.
        :param ephemeral_key: Preload an (CoseKey) ephemeral key (if unset a random key will be generated).
        """

        if conn_idi is None:
            conn_idi = os.urandom(1)

        super().__init__(cred,
                         cred_idi,
                         auth_key,
                         supported_ciphers,
                         conn_idi,
                         remote_cred_cb,
                         aad1_cb,
                         aad2_cb,
                         aad3_cb,
                         ephemeral_key)

        self._selected_cipher = CipherSuite.from_id(selected_cipher)
        self._corr = Correlation(corr)
        self._method = Method(method)

    @property
    def cipher_suite(self) -> 'CS':
        return self._selected_cipher

    @property
    def corr(self) -> Correlation:
        return self._corr

    @property
    def method(self) -> Method:
        return self._method

    @property
    def conn_idi(self):
        if self.corr in [Correlation.CORR_1, Correlation.CORR_3]:
            conn_idi = b''
        else:
            conn_idi = self._conn_id

        return conn_idi

    @property
    def conn_idr(self):
        if self.corr in [Correlation.CORR_2, Correlation.CORR_3]:
            conn_idr = b''
        else:
            conn_idr = self.msg_2.conn_idr

        return conn_idr

    @property
    def cred_idi(self) -> CoseHeaderMap:
        return self.cred_id

    @property
    def cred_idr(self) -> CoseHeaderMap:
        return self._cred_idr

    @cred_idr.setter
    def cred_idr(self, value):
        if isinstance(value, int):
            value = {4: EdhocMessage.decode_bstr_id(value)}
        elif isinstance(value, bytes):
            value = {4: value}

        self._cred_idr = value
        self._populate_remote_details(value)

    @property
    def g_y(self) -> bytes:
        return self.msg_2.g_y

    @property
    def g_x(self) -> bytes:

        self._generate_ephemeral_key()

        return self.ephemeral_key.x

    @property
    def local_pubkey(self) -> RPK:
        """ Returns the local ephemeral public key. """

        if self.cipher_suite.dh_curve in [X448, X25519]:
            return OKPKey(x=self.g_x, crv=self.cipher_suite.dh_curve)
        else:
            # TODO:
            pass

    @property
    def remote_pubkey(self) -> RPK:
        """ Returns the remote ephemeral public key. """

        if self.cipher_suite.dh_curve in [X448, X25519]:
            return OKPKey(x=self.g_y, crv=self.cipher_suite.dh_curve)
        else:
            # TODO:
            pass

    @property
    def local_authkey(self) -> RPK:
        return self._local_authkey

    def signature_or_mac3(self, mac_3: bytes):
        return self._signature_or_mac(mac_3, self._th3_input, self.aad3_cb)

    def create_message_one(self) -> bytes:
        self._generate_ephemeral_key()

        self.msg_1 = MessageOne(
            method_corr=self._method * 4 + self._corr,
            cipher_suites=self.supported_ciphers,
            selected_cipher=self._selected_cipher,
            g_x=self.g_x,
            conn_idi=self._conn_id,
        )

        self._internal_state = EdhocState.MSG_1_SENT

        return self.msg_1.encode(self.corr)

    def create_message_three(self, message_two: bytes):

        self.msg_2 = MessageTwo.decode(message_two)

        self._internal_state = EdhocState.MSG_2_RCVD

        decoded = EdhocMessage.decode(self._decrypt(self.msg_2.ciphertext))

        self.cred_idr = decoded[0]

        if not self._verify_signature_or_mac2(signature_or_mac2=decoded[1]):
            self._internal_state = EdhocState.EDHOC_FAIL
            return MessageError(err_msg='Signature verification failed').encode()

        try:
            ad_2 = decoded[2]
            if self.aad2_cb is not None:
                self.aad2_cb(ad_2)
        except IndexError:
            pass

        self.msg_3 = MessageThree(self.ciphertext_3, self.conn_idr)

        self._internal_state = EdhocState.MSG_3_SENT

        return self.msg_3.encode(self.corr)

    def _verify_signature_or_mac2(self, signature_or_mac2: bytes) -> bool:
        mac_2 = self._mac(self.cred_idr, self.remote_cred, self._hkdf2, 'K_2m', 16, 'IV_2m', 13, self._th2_input, self._prk3e2m, self.aad2_cb)

        if not self.is_static_dh(self.remote_role):
            external_aad = self._external_aad(self.remote_cred, self._th2_input, self.aad2_cb)
            cose_sign = Sign1Message(
                phdr=self.cred_idr,
                uhdr={headers.Algorithm: self.cipher_suite.sign_alg},
                payload=mac_2,
                external_aad=external_aad)
            # FIXME peeking into internals (probably best resolved at pycose level)
            cose_sign.key = self.remote_authkey
            cose_sign._signature = signature_or_mac2
            return cose_sign.verify_signature()
        else:
            return signature_or_mac2 == mac_2

    def finalize(self) -> Tuple[bytes, bytes, int, int]:
        """
        Finalizes the key exchange.

        :return: A 4-tuple containing the initiator and responder's connection identifiers and the application AEAD and\
         hash algorithms.
        """

        self._internal_state = EdhocState.EDHOC_SUCC

        app_aead = self.cipher_suite.app_aead
        app_hash = self.cipher_suite.app_hash

        # pass the connection identifiers and the algorithms identifiers
        return self._conn_id, self.msg_2.conn_idr, app_aead.identifier, app_hash.identifier

    @property
    def ciphertext_3(self):
        # TODO: resolve magic key and IV lengths
        iv_bytes = self._hkdf3(13, 'IV_3ae', self._prk3e2m)

        # TODO: resolve magic key and IV lengths
        cose_key = self._create_cose_key(self._hkdf3, 16, 'K_3ae', self._prk3e2m, [EncryptOp])

        # create payload for the COSE_Encrypt0
        payload = [self._p_3ae]

        if self.aad3_cb is not None:
            payload.append(self.aad3_cb())

        payload = b''.join(payload)

        # create the external data for the COSE_Encrypt0
        th_3 = self.transcript(self.cipher_suite.hash.hash_cls, self._th3_input)

        # calculate the mac_2 using a COSE_Encrypt0 message
        ciphertext = Enc0Message(uhdr={headers.IV: iv_bytes, headers.Algorithm: self.cipher_suite.aead},
                                 key=cose_key,
                                 payload=payload,
                                 external_aad=th_3).encrypt()

        return ciphertext

    @property
    def _hkdf2(self) -> Callable:
        return functools.partial(super()._hkdf_expand, transcript=self._th2_input)

    @property
    def _hkdf3(self) -> Callable:
        return functools.partial(super()._hkdf_expand, transcript=self._th3_input)

    def _prk3e2m_static_dh(self, prk: bytes):
        return self._prk(self.ephemeral_key, self.remote_authkey, prk)

    def _prk4x3m_static_dh(self, prk: bytes):
        return self._prk(self.auth_key, self.remote_pubkey, prk)

    @property
    def _p_3ae(self):
        # TODO: resolve magic key and IV lengths
        mac_3 = self._mac(self.cred_idi, self.cred, self._hkdf3, 'K_3m', 16, 'IV_3m', 13, self._th3_input, self._prk4x3m, self.aad3_cb)

        signature = self.signature_or_mac3(mac_3)

        if KID.identifier in self.cred_id:
            cred_id = EdhocMessage.encode_bstr_id(self.cred_id[KID.identifier])
        else:
            cred_id = self.cred_id

        return b"".join([cbor2.dumps(cred_id, default=EdhocRole._custom_cbor_encoder), cbor2.dumps(signature)])

    def _decrypt(self, ciphertext: bytes) -> bytes:
        length = len(ciphertext)
        xord = int.from_bytes(ciphertext, "big") ^ int.from_bytes(self._hkdf2(length, "KEYSTREAM_2", self._prk2e),
                                                                  "big")
        return xord.to_bytes((xord.bit_length() + 7) // 8, byteorder="big")
