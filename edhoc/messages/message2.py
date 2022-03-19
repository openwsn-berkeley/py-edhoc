from typing import Optional, TYPE_CHECKING

import cbor2

from edhoc.definitions import Correlation
from edhoc.messages.base import EdhocMessage

if TYPE_CHECKING:
    from edhoc.roles.edhoc import CBOR


class MessageTwo(EdhocMessage):
    CIPHERTEXT = -1
    CONN_ID_R = -2
    G_Y = -3

    @classmethod
    def decode(cls, received) -> 'MessageTwo':
        """
        Tries to decode the bytes as an EDHOC MessageTwo object

        :param received: Bytes to decode
        :return: An EDHOC MessageTwo object.
        """

        decoded = super().decode(received)
        ciphertext = decoded[cls.CIPHERTEXT]
        conn_idr = cls.decode_bstr_id(decoded[cls.CONN_ID_R])
        g_y = decoded[cls.G_Y]

        return cls(g_y, conn_idr, ciphertext)

    @classmethod
    def data_2(cls, g_y: bytes, conn_idr: bytes, corr: Correlation) -> 'CBOR':
        """ Create the data_2 message part. """

        data_2 = [g_y, EdhocMessage.encode_bstr_id(conn_idr)]

        return b''.join(cbor2.dumps(part) for part in data_2)

    def __init__(self, g_y: bytes, conn_idr: bytes, ciphertext: bytes):
        """
        Creates an EDHOC MessageTwo object.
        """

        self.conn_idr = conn_idr
        self.g_y = g_y
        self.ciphertext = ciphertext

    def encode(self, corr: Correlation) -> bytes:
        """ Encode EDHOC message 2. """

        return b''.join([self.data_2(self.g_y, self.conn_idr, corr), cbor2.dumps(self.ciphertext)])

    def __repr__(self) -> str:
        output = f'<MessageTwo: [{EdhocMessage._truncate(self.g_y)}, {self.conn_idr}, {self.ciphertext}>'

        return output
