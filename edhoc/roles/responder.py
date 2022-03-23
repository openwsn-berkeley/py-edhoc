import functools
from typing import List, Callable, Optional, Union, Tuple, TYPE_CHECKING, Type

import cbor2
from asn1crypto.x509 import Certificate
from cose import headers
from cose.keys.curves import X25519, X448
from cose.headers import KID
from cose.keys import OKPKey, EC2Key
from cose.keys.keyops import DecryptOp
from cose.messages import Enc0Message, Sign1Message

from edhoc.definitions import CipherSuite, Correlation, EdhocState, cborstream, compress_id_cred_x, bytewise_xor
from edhoc.exceptions import EdhocException
from edhoc.messages import MessageOne, MessageError, MessageThree, EdhocMessage, MessageTwo
from edhoc.roles.edhoc import EdhocRole, RPK, CoseHeaderMap

if TYPE_CHECKING:
    from edhoc.definitions import CS
    from cose.keys.cosekey import CK


class Responder(EdhocRole):
    role = 'R'
    remote_role = 'I'

    def __init__(self,
                 cred_local: Union[RPK, Certificate],
                 id_cred_r: CoseHeaderMap,
                 auth_key: RPK,
                 supported_ciphers: List[Type['CS']],
                 remote_cred_cb: Callable[[CoseHeaderMap], Union[Certificate, RPK]],
                 c_r: Union[bytes, int],
                 aad1_cb: Optional[Callable[..., bytes]] = None,
                 aad2_cb: Optional[Callable[..., bytes]] = None,
                 aad3_cb: Optional[Callable[..., bytes]] = None,
                 ephemeral_key: Optional['CK'] = None):
        """
        Create an EDHOC responder.

        :param cred_local: The public authentication credentials of the Responder.
        :param id_cred_r: The Responder's credential identifier (a CBOR encoded COSE header map)
        :param auth_key: The private authentication key (CoseKey) of the Responder.
        :param supported_ciphers: A list of ciphers supported by the Responder.
        :param c_r: The connection identifier of the Responder.
        :param remote_cred_cb: A callback that fetches the remote credentials
        :param aad1_cb: A callback to pass received additional data to the application protocol.
        :param aad2_cb: A callback to pass additional data to the remote endpoint.
        :param aad3_cb: A callback to pass received additional data to the application protocol.
        :param ephemeral_key: Preload an (CoseKey) ephemeral key (if unset a random key will be generated).
        """

        super().__init__(cred_local,
                         id_cred_r,
                         auth_key,
                         supported_ciphers,
                         c_r,
                         remote_cred_cb,
                         aad1_cb,
                         aad2_cb,
                         aad3_cb,
                         ephemeral_key)

    @property
    def cipher_suite(self) -> 'CS':
        if self.msg_1 is None:
            raise EdhocException("Message 1 not received. Cannot derive selected cipher suite.")
        else:
            if not self._verify_cipher_selection(self.msg_1.selected_cipher, self.msg_1.cipher_suites):
                raise EdhocException("Invalid cipher suite setup")
            return CipherSuite.from_id(self.msg_1.selected_cipher)

    @property
    def method(self):
        """ Get the EDHOC method value for the method parameter in EDHOC message 1. """

        if self.msg_1 is None:
            raise EdhocException("Message 1 not received. Cannot derive selected cipher suite.")

        return self.msg_1.method

    @property
    def c_i(self):
        return self.msg_1.c_i

    @property
    def c_r(self):
        return self._c_local

    @property
    def id_cred_i(self) -> CoseHeaderMap:
        return self._id_cred_i

    @id_cred_i.setter
    def id_cred_i(self, value):
        if isinstance(value, int):
            value = {4: EdhocMessage.decode_bstr_id(value)}
        elif isinstance(value, bytes):
            value = {4: value}

        self._id_cred_i = value
        self._populate_remote_details(value)

    @property
    def id_cred_r(self) -> CoseHeaderMap:
        return self.id_cred_local

    @property
    def ciphertext_2(self) -> bytes:
        """ Create the ciphertext_2 message part from EDHOC message 2. """

        # FIXME
        ead_2 = []

        if self.is_static_dh('R'):
            signature_or_mac_2 = self.mac_2
        else:
            # FIXME deduplicate
            cose_sign = Sign1Message(
                phdr=self.id_cred_local,
                uhdr={headers.Algorithm: self.cipher_suite.sign_alg},
                payload=self.mac_2,
                key=self.auth_key,
                external_aad=cborstream([self.th_2, self.cred_r, *ead_2]))
            signature_or_mac_2 = cose_sign.compute_signature()

        plaintext = cborstream([compress_id_cred_x(self.id_cred_r), signature_or_mac_2, *ead_2])
        keystream_2 = self.edhoc_kdf(self.prk_2e, self.th_2, "KEYSTREAM_2", b"", len(plaintext))

        return bytewise_xor(plaintext, keystream_2)

    @property
    def g_y(self) -> bytes:

        self._generate_ephemeral_key()

        return self.ephemeral_key.x

    @property
    def g_x(self) -> bytes:
        return self.msg_1.g_x

    @property
    def local_pubkey(self) -> RPK:
        """ Returns the local ephemeral public key. """

        # Is this a good criterion? (Possibly there doesn't need to be a
        # distinction; self.cipher_suite.dh_curve.keyclass(...) could do)
        if self.cipher_suite.dh_curve in [X448, X25519]:
            return OKPKey(x=self.g_y, crv=self.cipher_suite.dh_curve)
        else:
            return EC2Key(x=self.g_y, crv=self.cipher_suite.dh_curve)

    @property
    def remote_pubkey(self) -> RPK:
        """ Returns the remote ephemeral public key. """

        if self.cipher_suite.dh_curve in [X448, X25519]:
            return OKPKey(x=self.g_x, crv=self.cipher_suite.dh_curve)
        else:
            return EC2Key(x=self.g_x, crv=self.cipher_suite.dh_curve)

    @property
    def local_authkey(self) -> RPK:
        return self._local_authkey

    def create_message_two(self, message_one: MessageOne) -> bytes:
        """
        Decodes an incoming EDHOC message 1 and creates and EDHOC message 2 or error message based on the content
        of message 1.

        :param message_one: Bytes representing an EDHOC message 1.
        :returns: Bytes of an EDHOC message 2 or an EDHOC error message.
        """

        self.msg_1 = message_one

        self._internal_state = EdhocState.MSG_1_RCVD

        if not self._verify_cipher_selection(self.msg_1.selected_cipher, self.msg_1.cipher_suites):
            self._internal_state = EdhocState.EDHOC_FAIL

            return MessageError(err_msg="").encode()

        if self.aad1_cb is not None:
            self.aad1_cb(self.msg_1.aad1)

        self._generate_ephemeral_key()

        self.msg_2 = MessageTwo(self.g_y, self.c_r, self.ciphertext_2)

        self._internal_state = EdhocState.MSG_2_SENT
        # FIXME: Verify that "size" is actually what gives the g_y len -- only checked here because I'm unsure it is, and at least things will fail in a understandable place if that was wrong
        assert len(self.msg_2.g_y) == self.cipher_suite.dh_curve.size
        return self.msg_2.encode()

    def finalize(self, message_three: MessageThree) -> Union[Tuple[bytes, bytes, int, int], bytes]:
        """
        Decodes an incoming EDHOC message 3 and finalizes the key exchange.

        :param message_three: An EDHOC message 3
        :return: An EDHOC error message in case the verification of the EDHOC message 3 fails or a 4-tuple containing
         the initiator and responder's connection identifiers and the application AEAD and hash algorithms.
        """

        self.msg_3 = message_three

        self._internal_state = EdhocState.MSG_3_RCVD

        # FIXME how/where store
        self.ciphertext_3 = self.msg_3.ciphertext
        decoded = EdhocMessage.decode(self.decrypt_msg_3(self.ciphertext_3))

        self.id_cred_i = decoded[0]

        if not self._verify_signature_or_mac3(signature_or_mac3=decoded[1]):
            return MessageError(err_msg='Signature verification failed').encode()

        ad_3 = decoded[2:]
        assert not ad_3 # FIXME this is new
        if self.aad3_cb is not None:
            self.aad3_cb(ad_3)

        app_aead = self.cipher_suite.app_aead
        app_hash = self.cipher_suite.app_hash

        self._internal_state = EdhocState.EDHOC_SUCC

        return self.c_i, self.c_r, app_aead.identifier, app_hash.identifier

    def _verify_signature_or_mac3(self, signature_or_mac3: bytes) -> bool:
        # fixme
        ead_3 = []
        mac_3 = self.edhoc_kdf(self.prk_4x3m, self.th_3, "MAC_3", cborstream([self.id_cred_i, self.cred_i, *ead_3]), self.mac_length_3)

        if not self.is_static_dh(self.remote_role):
            cose_sign = Sign1Message(
                phdr=self.id_cred_i,
                uhdr={headers.Algorithm: self.cipher_suite.sign_alg},
                payload=mac_3,
                external_aad=cborstream([self.th_3, self.cred_i, *ead_3]))
            # FIXME peeking into internals (probably best resolved at pycose level)
            cose_sign.key = self.remote_authkey
            cose_sign._signature = signature_or_mac3
            return cose_sign.verify_signature()
        else:
            return signature_or_mac3 == mac_3

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

    def decrypt_msg_3(self, ciphertext: bytes) -> bytes:

        k_3 = self.edhoc_kdf(self.prk_3e2m, self.th_3, "K_3", b"", self.cipher_suite.aead.get_key_length())
        # FIXME IV lengthcA -- the object appears to still take 7 or 13...?
        iv_3 = self.edhoc_kdf(self.prk_3e2m, self.th_3, "IV_3", b"", 13)

        # FIXME
        from cose.keys import OKPKey, EC2Key, SymmetricKey
        from cose.keys.keyparam import KpKeyOps, KpAlg
        cose_key = SymmetricKey(k=k_3, optional_params={KpKeyOps: [DecryptOp], KpAlg: self.cipher_suite.aead})

        return Enc0Message(uhdr={headers.IV: iv_3, headers.Algorithm: self.cipher_suite.aead},
                           key=cose_key,
                           payload=ciphertext,
                           external_aad=self.th_3).decrypt()

    @property
    def shared_secret_rx(self):
        r = self.auth_key
        g_x = self.remote_pubkey
        return self.shared_secret(r, g_x)

    @property
    def shared_secret_iy(self):
        y = self.ephemeral_key
        g_i = self.remote_authkey
        return self.shared_secret(y, g_i)

    @property
    def cred_r(self):
        return self.cred_local

    @property
    def cred_i(self):
        return self.remote_cred
