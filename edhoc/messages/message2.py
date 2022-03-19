from typing import Optional, TYPE_CHECKING

import cbor2

from edhoc.definitions import Correlation
from edhoc.messages.base import EdhocMessage

if TYPE_CHECKING:
    from edhoc.roles.edhoc import CBOR


class MessageTwo(EdhocMessage):
    @classmethod
    def decode(cls, received, *, suite) -> 'MessageTwo':
        """
        Tries to decode the bytes as an EDHOC MessageTwo object

        :param received: Bytes to decode
        :return: An EDHOC MessageTwo object.
        """

        decoded = super().decode(received)
        (g_y_ciphertext, conn_idr) = decoded

        # FIXME: See create_message_two comment on the same property
        N = suite.dh_curve.size
        g_y = g_y_ciphertext[:N]
        ciphertext = g_y_ciphertext[N:]

        return cls(g_y, conn_idr, ciphertext)

    @classmethod
    def data_2(cls, g_y: bytes, conn_idr: bytes) -> 'CBOR':
        """ Create the data_2 message part. """

        data_2 = [g_y, conn_idr]

        return b''.join(cbor2.dumps(part) for part in data_2)

    def __init__(self, g_y: bytes, conn_idr: bytes, ciphertext: bytes):
        """
        Creates an EDHOC MessageTwo object.
        """

        self.conn_idr = conn_idr
        self.g_y = g_y
        self.ciphertext = ciphertext

    def encode(self) -> bytes:
        """ Encode EDHOC message 2. """

        return b''.join(cbor2.dumps(p) for p in (self.g_y + self.ciphertext, self.conn_idr))

    def __repr__(self) -> str:
        output = f'<MessageTwo: [{EdhocMessage._truncate(self.g_y)}, {self.conn_idr}, {self.ciphertext}>'

        return output
