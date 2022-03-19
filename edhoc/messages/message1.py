from binascii import hexlify
from typing import List, TYPE_CHECKING, Optional, Type

import cbor2

from edhoc.exceptions import EdhocInvalidMessage
from edhoc.messages.base import EdhocMessage
from edhoc.definitions import CipherSuite, Correlation

if TYPE_CHECKING:
    from edhoc.definitions import CS


class MessageOne(EdhocMessage):
    C_1 = 0
    METHOD_CORR = 1
    CIPHERS = 2
    G_X = 3
    CONN_ID = 4
    AAD1 = 5

    @classmethod
    def decode(cls, received) -> 'MessageOne':
        """
        Tries to decode the bytes as an EDHOC MessageOne.

        :param received: Bytes to decode.

        :raises EdhocInvalidMessage: Decoding routine for MessageOne failed.
        :returns: An EDHOC MessageOne object.
        """

        decoded = super().decode(received)

        method_corr = decoded[cls.METHOD_CORR]

        if decoded[cls.C_1] is not None:
            raise EdhocInvalidMessage("No leading nil")

        if isinstance(decoded[cls.CIPHERS], int):
            selected_cipher = decoded[cls.CIPHERS]
            supported_ciphers = [decoded[cls.CIPHERS]]
        elif isinstance(decoded[cls.CIPHERS], list):
            selected_cipher = decoded[cls.CIPHERS][0]
            supported_ciphers = decoded[cls.CIPHERS][1:]
        else:
            raise EdhocInvalidMessage("Failed to decode bytes as MessageOne")

        g_x = decoded[cls.G_X]

        if decoded[cls.CONN_ID] != b'':
            if isinstance(decoded[cls.CONN_ID], int):
                conn_idi = EdhocMessage.decode_bstr_id(decoded[cls.CONN_ID])
            else:
                conn_idi = decoded[cls.CONN_ID]
        else:
            conn_idi = b''

        msg = cls(
            method_corr=method_corr,
            selected_cipher=CipherSuite.from_id(selected_cipher),
            cipher_suites=[CipherSuite.from_id(c) for c in supported_ciphers],
            g_x=g_x,
            conn_idi=conn_idi)

        try:
            msg.aad1 = decoded[cls.AAD1]
        except IndexError:
            pass

        return msg

    def __init__(self,
                 method_corr: int,
                 cipher_suites: List['CS'],
                 selected_cipher: Type['CS'],
                 g_x: bytes,
                 conn_idi: Optional[bytes] = None,
                 external_aad: bytes = b''):

        """
        Creates an EDHOC MessageOne object.

        :param method_corr: Combination of the method parameter and correlation parameter (4 * method + correlation)
        :param cipher_suites: Supported cipher suites (ordered by decreasing preference).
        :param selected_cipher: The preferred cipher suite.
        :param g_x: The ephemeral public key of the Initiator.
        :param conn_idi: A variable length connection identifier.
        :param external_aad: Unprotected opaque auxiliary data (transferred together with EDHOC message 1).
        """

        self.method_corr = method_corr
        self.cipher_suites = cipher_suites
        self.selected_cipher = selected_cipher
        self.g_x = g_x
        self.conn_idi = conn_idi
        self.aad1 = external_aad

        self.corr = self.method_corr % 4
        self.method = (self.method_corr - self.corr) // 4

    def encode(self, corr: Correlation) -> bytes:
        """
        Encodes the first EDHOC message as a CBOR sequence.

        :returns: EDHOC message 1 encoded as bytes.
        """

        if len(self.cipher_suites) > 1:
            suites = [self.selected_cipher.identifier] + [c.identifier for c in self.cipher_suites]
        elif len(self.cipher_suites) == 1:
            suites = self.selected_cipher.identifier
        else:
            raise ValueError('Cipher suite list must contain at least 1 item.')

        msg = [None, self.method_corr, suites, self.g_x, self.encode_bstr_id(self.conn_idi)]

        if self.aad1 != b'':
            msg.append(cbor2.dumps(self.aad1))

        return b"".join(cbor2.dumps(chunk) for chunk in msg)

    def __repr__(self) -> str:
        output = f'<MessageOne: [{self.method_corr}, {self.selected_cipher} | {self.cipher_suites}, ' \
                 f'{EdhocMessage._truncate(self.g_x)}, {hexlify(self.conn_idi)}'
        if self.aad1 != b'':
            output += f'{hexlify(self.aad1)}'
        output += ']>'

        return output
