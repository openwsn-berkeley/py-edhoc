import functools
import os
from typing import List, Optional, Callable, Union, Tuple

import cbor2
from cose import KeyOps, Enc0Message, OKP, CoseHeaderKeys
from cose.attributes.algorithms import config as config_cose, CoseEllipticCurves

from edhoc.definitions import CipherSuite, Method, Correlation, EdhocState
from edhoc.messages import MessageOne, MessageTwo, MessageThree, EdhocMessage, MessageError
from edhoc.roles.edhoc import EdhocRole, CoseHeaderMap, Key


class Initiator(EdhocRole):

    def __init__(self,
                 corr: Correlation,
                 method: Method,
                 cred: bytes,
                 cred_idi: CoseHeaderMap,
                 auth_key: Key,
                 selected_cipher: CipherSuite,
                 supported_ciphers: List[CipherSuite],
                 peer_cred: Optional[Union[Callable[..., bytes], bytes]],
                 conn_idi: Optional[bytes] = None,
                 aad1_cb: Optional[Callable[..., bytes]] = None,
                 aad2_cb: Optional[Callable[..., bytes]] = None,
                 aad3_cb: Optional[Callable[..., bytes]] = None,
                 ephemeral_key: Optional[Key] = None):
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
        :param peer_cred: Provide the public authentication material for the remote peer, by a callback or directly.
        :param aad1_cb: A callback to pass received additional data to the application protocol.
        :param aad2_cb: A callback to pass additional data to the remote endpoint.
        :param aad3_cb: A callback to pass received additional data to the application protocol.
        :param ephemeral_key: Preload an (CoseKey) ephemeral key (if unset a random key will be generated).
        """

        if conn_idi is None:
            conn_idi = os.urandom(1)

        super().__init__(cred, cred_idi, auth_key, supported_ciphers, conn_idi, peer_cred, aad1_cb, aad2_cb, aad3_cb,
                         ephemeral_key)

        self._selected_cipher = CipherSuite(selected_cipher)
        self._corr = Correlation(corr)
        self._method = Method(method)

        self._cred_idr = None

    @property
    def cipher_suite(self) -> CipherSuite:
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

    @property
    def g_y(self) -> bytes:
        return self.msg_2.g_y

    @property
    def g_x(self) -> bytes:

        self._generate_ephemeral_key()

        return self.ephemeral_key.x

    @property
    def local_pubkey(self) -> Key:
        """ Returns the local ephemeral public key. """

        if self.cipher_suite.dh_curve in [CoseEllipticCurves.X448, CoseEllipticCurves.X25519]:
            return OKP(x=self.g_x, crv=self.cipher_suite.dh_curve)
        else:
            # TODO:
            pass

    @property
    def remote_pubkey(self) -> Key:
        """ Returns the remote ephemeral public key. """

        if self.cipher_suite.dh_curve in [CoseEllipticCurves.X448, CoseEllipticCurves.X25519]:
            return OKP(x=self.g_y, crv=self.cipher_suite.dh_curve)
        else:
            # TODO:
            pass

    @property
    def local_authkey(self) -> Key:
        return self._local_authkey

    @property
    def remote_authkey(self) -> Key:
        if hasattr(self._remote_authkey, '__call__'):
            return self._remote_authkey(self.cred_idr)
        else:
            return self._remote_authkey

    @property
    def peer_cred(self):
        if hasattr(self._peer_cred, '__call__'):
            self._peer_cred(self.cred_idr)
        else:
            return self._peer_cred

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

        return self.msg_1.encode()

    def create_message_three(self, message_two: bytes):

        self.msg_2 = MessageTwo.decode(message_two)

        self._internal_state = EdhocState.MSG_2_RCVD

        decoded = EdhocMessage.decode(self._decrypt(self.msg_2.ciphertext))

        self._cred_idr = decoded[0]

        if not self._verify_signature(signature=decoded[1]):
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

        return self.msg_3.encode()

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
        return self._conn_id, self.msg_2.conn_idr, app_aead.id, app_hash.id

    @property
    def ciphertext_3(self):
        # TODO: resolve magic key and IV lengths
        iv_bytes = self._hkdf3(13, 'IV_3ae', self._prk3e2m)

        hash_func = config_cose(self.cipher_suite.hash).hash
        # TODO: resolve magic key and IV lengths
        cose_key = self._create_cose_key(self._hkdf3, 16, 'K_3ae', self._prk3e2m, KeyOps.ENCRYPT)

        # create payload for the COSE_Encrypt0
        payload = [self._p_3ae]

        if self.aad3_cb is not None:
            payload.append(self.aad3_cb())

        payload = b''.join(payload)

        # create the external data for the COSE_Encrypt0
        th_3 = self.transcript(hash_func, self._th3_input)

        # calculate the mac_2 using a COSE_Encrypt0 message
        ciphertext = Enc0Message(payload=payload, external_aad=th_3).encrypt(iv_bytes, cose_key)

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
        mac_3 = self._mac(self._hkdf3, 'K_3m', 16, 'IV_3m', 13, self._th3_input, self._prk4x3m, self.aad3_cb)

        signature = self.signature_or_mac3(mac_3)

        if CoseHeaderKeys.KID in self.cred_id:
            cred_id = EdhocMessage.encode_bstr_id(self.cred_id[CoseHeaderKeys.KID])
        else:
            cred_id = self.cred_id

        return b"".join([cbor2.dumps(cred_id), cbor2.dumps(signature)])

    def _decrypt(self, ciphertext: bytes) -> bytes:
        length = len(ciphertext)
        xord = int.from_bytes(ciphertext, "big") ^ int.from_bytes(self._hkdf2(length, "K_2e", self._prk2e), "big")
        return xord.to_bytes((xord.bit_length() + 7) // 8, byteorder="big")
