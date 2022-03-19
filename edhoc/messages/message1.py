from binascii import hexlify
from typing import List, TYPE_CHECKING, Optional, Type

import cbor2

from edhoc.exceptions import EdhocInvalidMessage
from edhoc.messages.base import EdhocMessage
from edhoc.definitions import CipherSuite, Correlation

if TYPE_CHECKING:
    from edhoc.definitions import CS


class MessageOne(EdhocMessage):
    @classmethod
    def decode(cls, received) -> 'MessageOne':
        """
        Tries to decode the bytes as an EDHOC MessageOne.

        :param received: Bytes to decode.

        :raises EdhocInvalidMessage: Decoding routine for MessageOne failed.
        :returns: An EDHOC MessageOne object.
        """

        decoded = super().decode(received)

        (method, ciphers, g_x, conn_idi, *aad) = decoded

        if isinstance(ciphers, int):
            selected_cipher = ciphers
            supported_ciphers = [ciphers]
        elif isinstance(decoded[cls.CIPHERS], list):
            selected_cipher = ciphers[0]
            supported_ciphers = ciphers[1:]
        else:
            raise EdhocInvalidMessage("Failed to decode bytes as MessageOne")

        msg = cls(
            method=method,
            selected_cipher=CipherSuite.from_id(selected_cipher),
            cipher_suites=[CipherSuite.from_id(c) for c in supported_ciphers],
            g_x=g_x,
            conn_idi=conn_idi)

        if aad:
            raise NotImplementedError("AAD changed")

        return msg

    def __init__(self,
                 method: int,
                 cipher_suites: List['CS'],
                 selected_cipher: Type['CS'],
                 g_x: bytes,
                 conn_idi: Optional[bytes] = None,
                 external_aad: bytes = b''):

        """
        Creates an EDHOC MessageOne object.

        :param method: EDHOC method (indicating who signs / who does static derivation)
        :param cipher_suites: Supported cipher suites (ordered by decreasing preference).
        :param selected_cipher: The preferred cipher suite.
        :param g_x: The ephemeral public key of the Initiator.
        :param conn_idi: A variable length connection identifier.
        :param external_aad: Unprotected opaque auxiliary data (transferred together with EDHOC message 1).
        """

        self.method = method
        self.cipher_suites = cipher_suites
        self.selected_cipher = selected_cipher
        self.g_x = g_x
        self.conn_idi = conn_idi
        self.aad1 = external_aad

    def encode(self) -> bytes:
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

        msg = [self.method, suites, self.g_x, self.conn_idi]

        if self.aad1 != b'':
            raise NotImplementedError("AAD stuff changed")
            msg.append(cbor2.dumps(self.aad1))

        return b"".join(cbor2.dumps(chunk) for chunk in msg)

    def __repr__(self) -> str:
        output = f'<MessageOne: [{self.method}, {self.selected_cipher} | {self.cipher_suites}, ' \
                 f'{EdhocMessage._truncate(self.g_x)}, {hexlify(self.conn_idi)}'
        if self.aad1 != b'':
            output += f'{hexlify(self.aad1)}'
        output += ']>'

        return output
