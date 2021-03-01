from binascii import hexlify
from typing import List, TYPE_CHECKING, Optional

import cbor2

from edhoc.exceptions import EdhocInvalidMessage
from edhoc.messages.base import EdhocMessage

if TYPE_CHECKING:
    from edhoc.definitions import CipherSuite


class MessageOne(EdhocMessage):
    METHOD_CORR = 0
    CIPHERS = 1
    G_X = 2
    CONN_ID = 3
    AAD1 = 4

    @classmethod
    def decode(cls, received: bytes) -> 'MessageOne':
        """
        Tries to decode the bytes as an EDHOC MessageOne.

        :param received: Bytes to decode.
        :raises EdhocInvalidMessage: Decoding routine for MessageOne failed.
        :returns: An EDHOC MessageOne object.
        """

        decoded = super().decode(received)

        method_corr = decoded[cls.METHOD_CORR]

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
            selected_cipher=selected_cipher,
            cipher_suites=supported_ciphers,
            g_x=g_x,
            conn_idi=conn_idi)

        try:
            msg.aad1 = decoded[cls.AAD1]
        except IndexError:
            pass

        return msg

    def __init__(self,
                 method_corr: int,
                 cipher_suites: List['CipherSuite'],
                 selected_cipher: 'CipherSuite',
                 g_x: bytes,
                 conn_idi: Optional[bytes] = None,
                 external_aad: bytes = b''):

        """
        Creates an EDHOC MessageOne object.

        :param method_corr: Determines which connection identifiers that are omitted.
        :param cipher_suites: Cipher suites chosen by the Initiator (ordered by decreasing preference).
        :param selected_cipher: The selected cipher.
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

    def encode(self) -> bytes:
        """
        Encodes the first EDHOC message.

        :raises EdhocCipherException: Invalid cipher configuration.
        :returns: EDHOC message 1 encoded as bytes.
        """

        if len(self.cipher_suites) > 1:
            suites = [int(self.selected_cipher)] + self.cipher_suites
        elif len(self.cipher_suites) == 1:
            suites = int(self.selected_cipher)
        else:
            raise ValueError('Cipher suite list must contain at least 1 item.')

        msg = [self.method_corr, suites, self.g_x, self.encode_bstr_id(self.conn_idi)]

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
