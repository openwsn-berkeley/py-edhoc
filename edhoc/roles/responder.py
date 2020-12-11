import functools
import os
from typing import List, Callable, Optional, Union, Tuple

import cbor2
from cose import Enc0Message, KeyOps, OKP, CoseHeaderKeys
from cose.attributes.algorithms import config as config_cose, CoseEllipticCurves

from edhoc.definitions import CipherSuite, Correlation, EdhocState
from edhoc.exceptions import EdhocException
from edhoc.messages import MessageOne, MessageError, MessageThree, EdhocMessage, MessageTwo
from edhoc.roles.edhoc import EdhocRole, Key, CoseHeaderMap, CBOR


class Responder(EdhocRole):
    def __init__(self,
                 cred: CBOR,
                 cred_idr: CoseHeaderMap,
                 auth_key: Key,
                 supported_ciphers: List[CipherSuite],
                 peer_cred: Optional[Union[Callable[..., bytes], CBOR]],
                 conn_idr: Optional[bytes] = None,
                 aad1_cb: Optional[Callable[..., bytes]] = None,
                 aad2_cb: Optional[Callable[..., bytes]] = None,
                 aad3_cb: Optional[Callable[..., bytes]] = None,
                 ephemeral_key: Optional[Key] = None):
        """
        Create an EDHOC responder.

        :param cred: The public authentication credentials of the Responder.
        :param cred_idr: The Responder's credential identifier (a CBOR encoded COSE header map)
        :param auth_key: The private authentication key (CoseKey) of the Responder.
        :param supported_ciphers: A list of ciphers supported by the Responder.
        :param conn_idr: The connection identifier of the Responder.
        :param peer_cred: Provide the public authentication material for the remote peer, by a callback or directly.
        :param aad1_cb: A callback to pass received additional data to the application protocol.
        :param aad2_cb: A callback to pass additional data to the remote endpoint.
        :param aad3_cb: A callback to pass received additional data to the application protocol.
        :param ephemeral_key: Preload an (CoseKey) ephemeral key (if unset a random key will be generated).
        """

        if conn_idr is None:
            conn_idr = os.urandom(1)

        super().__init__(cred, cred_idr, auth_key, supported_ciphers, conn_idr, peer_cred, aad1_cb, aad2_cb, aad3_cb,
                         ephemeral_key)

        self._cred_idi = None

    @property
    def cipher_suite(self) -> CipherSuite:
        if self.msg_1 is None:
            raise EdhocException("Message 1 not received. Cannot derive selected cipher suite.")
        else:
            if not self._verify_cipher_selection(self.msg_1.selected_cipher, self.msg_1.cipher_suites):
                raise EdhocException("Invalid cipher suite setup")
            return CipherSuite(self.msg_1.selected_cipher)

    @property
    def corr(self):
        """ Get the EDHOC correlation value for the method_corr parameter in EDHOC message 1. """

        if self.msg_1 is None:
            raise EdhocException("Message 1 not received. Cannot derive selected cipher suite.")

        return self.msg_1.method_corr % 4

    @property
    def method(self):
        """ Get the EDHOC method value for the method_corr parameter in EDHOC message 1. """

        if self.msg_1 is None:
            raise EdhocException("Message 1 not received. Cannot derive selected cipher suite.")

        return (self.msg_1.method_corr - self.corr) // 4

    @property
    def conn_idi(self):
        if self.corr in [Correlation.CORR_1, Correlation.CORR_3]:
            conn_idi = b''
        else:
            conn_idi = self.msg_1.conn_idi

        return conn_idi

    @property
    def conn_idr(self):
        if self.corr in [Correlation.CORR_2, Correlation.CORR_3]:
            conn_idr = b''
        else:
            conn_idr = self._conn_id
        return conn_idr

    @property
    def cred_idi(self) -> CoseHeaderMap:
        return self._cred_idi

    @property
    def cred_idr(self) -> CoseHeaderMap:
        return self.cred_id

    @property
    def ciphertext_2(self) -> bytes:
        """ Create the ciphertext_2 message part from EDHOC message 2. """

        length = len(self._p_2e)
        xord = int.from_bytes(self._p_2e, "big") ^ int.from_bytes(self._hkdf2(length, "K_2e", self._prk2e), "big")
        return xord.to_bytes((xord.bit_length() + 7) // 8, byteorder="big")

    @property
    def g_y(self) -> bytes:

        self._generate_ephemeral_key()

        return self.ephemeral_key.x

    @property
    def g_x(self) -> bytes:
        return self.msg_1.g_x

    @property
    def local_pubkey(self) -> Key:
        """ Returns the local ephemeral public key. """

        if self.cipher_suite.dh_curve in [CoseEllipticCurves.X448, CoseEllipticCurves.X25519]:
            return OKP(x=self.g_y, crv=self.cipher_suite.dh_curve)
        else:
            # TODO: implement NIST curves
            pass

    @property
    def remote_pubkey(self) -> Key:
        """ Returns the remote ephemeral public key. """

        if self.cipher_suite.dh_curve in [CoseEllipticCurves.X448, CoseEllipticCurves.X25519]:
            return OKP(x=self.g_x, crv=self.cipher_suite.dh_curve)
        else:
            # TODO: implement NIST curves
            pass

    @property
    def local_authkey(self) -> Key:
        return self._local_authkey

    @property
    def remote_authkey(self) -> Key:
        if hasattr(self._remote_authkey, '__call__'):
            return self._remote_authkey(self.cred_idi)
        else:
            return self._remote_authkey

    @property
    def peer_cred(self):
        if hasattr(self._peer_cred, '__call__'):
            self._peer_cred(self.cred_idi)
        else:
            return self._peer_cred

    def signature_or_mac2(self, mac_2: bytes):
        return self._signature_or_mac(mac_2, self._th2_input, self.aad2_cb)

    def create_message_two(self, message_one: bytes) -> bytes:
        """
        Decodes an incoming EDHOC message 1 and creates and EDHOC message 2 or error message based on the content
        of message 1.

        :param message_one: Bytes representing an EDHOC message 1.
        :returns: Bytes of an EDHOC message 2 or an EDHOC error message.
        """

        self.msg_1 = MessageOne.decode(message_one)

        self._internal_state = EdhocState.MSG_1_RCVD

        if not self._verify_cipher_selection(self.msg_1.selected_cipher, self.msg_1.cipher_suites):
            self._internal_state = EdhocState.EDHOC_FAIL

            return MessageError(err_msg="").encode()

        if self.aad1_cb is not None:
            self.aad1_cb(self.msg_1.aad1)

        self._generate_ephemeral_key()

        self.msg_2 = MessageTwo(self.g_y, self.conn_idr, self.ciphertext_2, self.conn_idi)

        self._internal_state = EdhocState.MSG_2_SENT
        return self.msg_2.encode()

    def finalize(self, message_three: bytes) -> Union[Tuple[bytes, bytes, int, int], bytes]:
        """
        Decodes an incoming EDHOC message 3 and finalizes the key exchange.

        :param message_three: An EDHOC message 3
        :return: An EDHOC error message in case the verification of the EDHOC message 3 fails or a 4-tuple containing
         the initiator and responder's connection identifiers and the application AEAD and hash algorithms.
        """

        self.msg_3 = MessageThree.decode(message_three)

        self._internal_state = EdhocState.MSG_3_RCVD

        decoded = EdhocMessage.decode(self._decrypt(self.msg_3.ciphertext))

        self._cred_idi = decoded[0]

        if not self._verify_signature(signature=decoded[1]):
            return MessageError(err_msg='').encode()

        try:
            ad_3 = decoded[2]
            if self.aad3_cb is not None:
                self.aad3_cb(ad_3)
        except IndexError:
            pass

        app_aead = self.cipher_suite.app_aead
        app_hash = self.cipher_suite.app_hash

        self._internal_state = EdhocState.EDHOC_SUCC

        return self.msg_1.conn_idi, self._conn_id, app_aead.id, app_hash.id

    @property
    def _hkdf2(self) -> Callable:
        return functools.partial(super()._hkdf_expand, transcript=self._th2_input)

    @property
    def _hkdf3(self) -> Callable:
        return functools.partial(super()._hkdf_expand, transcript=self._th3_input)

    @property
    def _p_2e(self):
        # compute MAC_2
        # TODO: resolve magic key and IV lengths
        mac_2 = self._mac(self._hkdf2, 'K_2m', 16, 'IV_2m', 13, self._th2_input, self._prk3e2m, self.aad2_cb)

        # compute the signature_or_mac2
        signature = self.signature_or_mac2(mac_2)

        if CoseHeaderKeys.KID in self.cred_id:
            cred_id = EdhocMessage.encode_bstr_id(self.cred_id[CoseHeaderKeys.KID])
        else:
            cred_id = self.cred_id

        return b"".join([cbor2.dumps(cred_id), cbor2.dumps(signature)])

    def _prk3e2m_static_dh(self, prk: bytes):
        return self._prk(self.auth_key, self.remote_pubkey, prk)

    def _prk4x3m_static_dh(self, prk: bytes):
        return self._prk(self.ephemeral_key, self.remote_authkey, prk)

    def _verify_cipher_selection(self, selected: CipherSuite, supported: List[CipherSuite]) -> bool:
        """
        Checks if the selected cipher suite is supported and that no prior cipher suites in the Initiator's list of
        supported ciphers is supported by the Responder.

        :param selected: the cipher suite selected by the Initiator
        :param supported: the list of cipher suites supported by the Initiator
        :return: True or False
        """

        if selected not in self.supported_ciphers:
            return False

        for sc in supported:
            if sc in self.supported_ciphers and sc != selected:
                return False
            elif sc in self.supported_ciphers and sc == selected:
                return True
            else:
                continue

        return True

    def _decrypt(self, ciphertext: bytes) -> bytes:
        # TODO: resolve magic key and IV lengths
        iv_bytes = self._hkdf3(13, 'IV_3ae', self._prk3e2m)

        hash_func = config_cose(self.cipher_suite.hash).hash
        # TODO: resolve magic key and IV lengths
        cose_key = self._create_cose_key(self._hkdf3, 16, 'K_3ae', self._prk3e2m, KeyOps.DECRYPT)

        th_3 = self.transcript(hash_func, self._th3_input)

        return Enc0Message(payload=ciphertext, external_aad=th_3).decrypt(iv_bytes, cose_key)
