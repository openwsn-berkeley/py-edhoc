import functools
from typing import List, Optional, Callable, Union, Tuple, TYPE_CHECKING, Type

import cbor2
from asn1crypto.x509 import Certificate
from cose import headers
from cose.keys.curves import X448, X25519
from cose.headers import KID
from cose.keys import OKPKey, EC2Key
from cose.keys.keyops import EncryptOp
from cose.messages import Enc0Message, Sign1Message

from edhoc.definitions import CipherSuite, Method, Correlation, EdhocState, bytewise_xor, cborstream, compress_id_cred_x
from edhoc.messages import MessageOne, MessageTwo, MessageThree, EdhocMessage, MessageError
from edhoc.roles.edhoc import EdhocRole, CoseHeaderMap, RPK, cached_property_singledelete

if TYPE_CHECKING:
    from edhoc.definitions import CS
    from cose.keys.cosekey import CK


class Initiator(EdhocRole):
    role = 'I'
    remote_role = 'R'

    def __init__(self,
                 method: Method,
                 cred_local: Cred,
                 id_cred_i: CoseHeaderMap,
                 auth_key: RPK,
                 selected_cipher: Type['CS'],
                 supported_ciphers: List[Type['CS']],
                 remote_cred_cb:  Callable[[CoseHeaderMap], Cred],
                 c_i: Union[bytes, int],
                 aad1_cb: Optional[Callable[..., bytes]] = None,
                 aad2_cb: Optional[Callable[..., bytes]] = None,
                 aad3_cb: Optional[Callable[..., bytes]] = None,
                 ephemeral_key: Optional['CK'] = None):
        """
        Create an EDHOC Initiator.

        :param method: EDHOC method type (signatures, static DH or a mix).
        :param cred_local: The public authentication credentials of the Initiator.
        :param id_cred_i: The Initiator's credential identifier (a CBOR encoded COSE header map)
        :param auth_key: The private authentication key (CoseKey) of the Responder.
        :param selected_cipher: Provide the selected cipher.
        :param supported_ciphers: A list of ciphers supported by the Responder.
        :param c_i: The connection identifier to be used
        :param remote_cred_cb: A callback that fetches the remote credentials.
        :param aad1_cb: A callback to pass received additional data to the application protocol.
        :param aad2_cb: A callback to pass additional data to the remote endpoint.
        :param aad3_cb: A callback to pass received additional data to the application protocol.
        :param ephemeral_key: Preload an (CoseKey) ephemeral key (if unset a random key will be generated).
        """

        super().__init__(cred_local,
                         id_cred_i,
                         auth_key,
                         supported_ciphers,
                         remote_cred_cb,
                         aad1_cb,
                         aad2_cb,
                         aad3_cb,
                         ephemeral_key)

        self.c_i = c_i

        self.cipher_suite = CipherSuite.from_id(selected_cipher)
        self.method = Method(method)

    @property
    def id_cred_i(self) -> CoseHeaderMap:
        return self.id_cred_local

    @property
    def id_cred_r(self) -> CoseHeaderMap:
        return self._id_cred_r

    @id_cred_r.setter
    def id_cred_r(self, value):
        if isinstance(value, int):
            value = {4: EdhocMessage.decode_bstr_id(value)}
        elif isinstance(value, bytes):
            value = {4: value}

        self._id_cred_r = value
        self._populate_remote_details(value)

    @property
    def g_y(self) -> bytes:
        return self._g_y

    @property
    def g_x(self) -> bytes:
        return self.ephemeral_key.x

    @property
    def local_pubkey(self) -> RPK:
        """ Returns the local ephemeral public key. """

        if self.cipher_suite.dh_curve in [X448, X25519]:
            return OKPKey(x=self.g_x, crv=self.cipher_suite.dh_curve)
        else:
            return EC2Key(x=self.g_x, crv=self.cipher_suite.dh_curve)

    @property
    def remote_pubkey(self) -> RPK:
        """ Returns the remote ephemeral public key. """

        if self.cipher_suite.dh_curve in [X448, X25519]:
            return OKPKey(x=self.g_y, crv=self.cipher_suite.dh_curve)
        else:
            return EC2Key(x=self.g_y, crv=self.cipher_suite.dh_curve)

    @property
    def local_authkey(self) -> RPK:
        return self._local_authkey

    def create_message_one(self) -> bytes:
        self._generate_ephemeral_key()

        msg_1 = MessageOne(
            method=self.method,
            cipher_suites=self.supported_ciphers,
            selected_cipher=self.cipher_suite,
            g_x=self.g_x,
            c_i=self.c_i,
        )

        self._internal_state = EdhocState.MSG_1_SENT

        encoded = msg_1.encode()
        self.hash_of_message_1 = self.hash(encoded)
        return encoded

    def create_message_three(self, message_two: bytes):

        msg_2 = MessageTwo.decode(message_two, suite=self.cipher_suite)
        self.c_r = msg_2.c_r
        self._g_y = msg_2.g_y

        self._internal_state = EdhocState.MSG_2_RCVD

        decoded = EdhocMessage.decode(self.decrypt_msg_2(msg_2.ciphertext))

        self.id_cred_r = decoded[0]

        if not self._verify_signature_or_mac2(signature_or_mac2=decoded[1]):
            self._internal_state = EdhocState.EDHOC_FAIL
            return MessageError(err_msg='Signature verification failed').encode()

        ad_2 = decoded[2:]
        assert not ad_2 # FIXME this is new
        if self.aad2_cb is not None:
            self.aad2_cb(ad_2)

        msg_3 = MessageThree(self.ciphertext_3)

        self._internal_state = EdhocState.MSG_3_SENT

        return msg_3.encode()

    def _verify_signature_or_mac2(self, signature_or_mac2: bytes) -> bool:
        # FIXME
        ead_2 = []

        if not self.is_static_dh(self.remote_role):
            cose_sign = Sign1Message(
                phdr=self.id_cred_r,
                uhdr={headers.Algorithm: self.cipher_suite.sign_alg},
                payload=self.mac_2,
                external_aad=cborstream([self.th_2, self.cred_r, *ead_2]))
            # FIXME peeking into internals (probably best resolved at pycose level)
            cose_sign.key = self.remote_authkey
            cose_sign._signature = signature_or_mac2
            return cose_sign.verify_signature()
        else:
            return signature_or_mac2 == self.mac_2

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
        return self.c_i, self.c_r, app_aead.identifier, app_hash.identifier

    @cached_property_singledelete
    def ciphertext_3(self):
        # FIXME
        ead_3 = []

        if self.is_static_dh('I'):
            signature_or_mac_3 = self.mac_3
        else:
            # FIXME deduplicate
            cose_sign = Sign1Message(
                phdr=self.id_cred_local,
                uhdr={headers.Algorithm: self.cipher_suite.sign_alg},
                payload=self.mac_3,
                key=self.auth_key,
                external_aad=cborstream([self.th_3, self.cred_i, *ead_3]))
            signature_or_mac_3 = cose_sign.compute_signature()

        k_3 = self.edhoc_kdf(self.prk_3e2m, self.th_3, "K_3", b"", self.cipher_suite.aead.get_key_length())
        # FIXME IV lengthcA -- the object appears to still take 7 or 13...?
        iv_3 = self.edhoc_kdf(self.prk_3e2m, self.th_3, "IV_3", b"", 13)

        # FIXME
        from cose.keys import OKPKey, EC2Key, SymmetricKey
        from cose.keys.keyparam import KpKeyOps, KpAlg
        cose_key = SymmetricKey(k=k_3, optional_params={KpKeyOps: [EncryptOp], KpAlg: self.cipher_suite.aead})

        plaintext = [compress_id_cred_x(self.id_cred_i), signature_or_mac_3, *ead_3]
        # TBD does the spec say that?
        payload = cborstream(plaintext)

        ciphertext = Enc0Message(uhdr={headers.IV: iv_3, headers.Algorithm: self.cipher_suite.aead},
                                 key=cose_key,
                                 payload=payload,
                                 external_aad=self.th_3).encrypt()

        return ciphertext

    def decrypt_msg_2(self, ciphertext: bytes) -> bytes:
        # FIXME
        ead_2 = []

        # FIXME why/how store that?
        self.ciphertext_2 = ciphertext

        keystream_2 = self.edhoc_kdf(self.prk_2e, self.th_2, "KEYSTREAM_2", b"", len(ciphertext))

        return bytewise_xor(ciphertext, keystream_2)

    @cached_property_singledelete
    def shared_secret_rx(self):
        x = self.ephemeral_key
        g_r = self.remote_authkey
        return self.shared_secret(x, g_r)

    @cached_property_singledelete
    def shared_secret_iy(self):
        i = self.auth_key
        g_y = self.remote_pubkey
        return self.shared_secret(i, g_y)

    @property
    def cred_r(self):
        return self.remote_cred

    @property
    def cred_i(self):
        return self.cred_local
