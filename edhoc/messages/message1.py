from typing import List, TYPE_CHECKING

import cbor2

from edhoc.exceptions import EdhocCipherException, EdhocInvalidMessage
from edhoc.messages.base import EdhocMessage

if TYPE_CHECKING:
    from edhoc.definitions import Correlation, CipherSuite


class MessageOne(EdhocMessage):
    @classmethod
    def decode(cls, received: bytes, corr: 'Correlation') -> 'MessageOne':
        """
        Tries to decode the bytes as an EDHOC MessageOne.

        :param received: Bytes to decode.
        :param corr: Correlation value for transport protocol.
        :raises EdhocInvalidMessage: Decoding routine for MessageOne failed.
        :returns: An EDHOC MessageOne object.
        """

        decoded = []
        while len(received) > 0:
            decoded += [cbor2.loads(received)]
            received = received[received.startswith(cbor2.dumps(decoded[-1])) and len(cbor2.dumps(decoded[-1])):]

        if isinstance(decoded[1], int):
            selected_cipher = decoded[1]
            supported_ciphers = [decoded[1]]
        elif isinstance(decoded[1], list):
            selected_cipher = decoded[1][0]
            supported_ciphers = decoded[1:]
        else:
            raise EdhocInvalidMessage("Failed to decode bytes as MessageOne")

        method = (decoded[0] - corr) // 4
        g_x = decoded[2]

        msg = cls(corr=corr, method=method, selected_cipher=selected_cipher, cipher_suites=supported_ciphers, g_x=g_x)

        try:
            msg.conn_idi = decoded[3]
        except IndexError:
            pass

        try:
            msg.aad1 = decoded[4]
        except IndexError:
            pass

        return msg

    def __init__(self,
                 corr: int,
                 method: int,
                 cipher_suites: List['CipherSuite'],
                 selected_cipher: 'CipherSuite',
                 g_x: bytes,
                 conn_idi: bytes = b'',
                 external_aad: bytes = b''):

        """
        Creates an EDHOC MessageOne object.

        :param corr: Determines which connection identifiers that are omitted.
        :param method: Sets the authentication method (combinations of Signature / Static Diffie-Hellman)
        :param cipher_suites: Cipher suites chosen by the Initiator (ordered by decreasing preference).
        :param selected_cipher: The selected cipher.
        :param g_x: The ephemeral public key of the Initiator.
        :param conn_idi: A variable length connection identifier.
        :param external_aad: Unprotected opaque auxiliary data (transferred together with EDHOC message 1).
        """

        self.corr = corr
        self.method = method
        self.cipher_suites = cipher_suites
        self.selected_cipher = selected_cipher
        self.g_x = g_x
        self.conn_idi = conn_idi
        self.aad1 = external_aad

    @property
    def method_corr(self):
        return self.method * 4 + self.corr

    def encode(self) -> bytes:
        """
        Encodes the first EDHOC message.

        :raises EdhocCipherException: Invalid cipher configuration.
        :returns: EDHOC message 1 encoded as bytes.
        """

        if self.selected_cipher not in self.cipher_suites:
            raise EdhocCipherException("Selected cipher is not included in the supported cipher suite.")

        if len(self.cipher_suites) > 1:
            suites = [self.selected_cipher] + self.cipher_suites
        elif len(self.cipher_suites) == 1:
            suites = self.selected_cipher
        else:
            raise ValueError('Cipher suite list must contain at least 1 item.')

        msg = [self.method_corr, suites, self.g_x, self.conn_idi]

        if self.aad1 != b'':
            msg.append(self.aad1)

        return b"".join([cbor2.dumps(msg_part) for msg_part in msg])
