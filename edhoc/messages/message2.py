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
    CONN_ID_I = -4

    @classmethod
    def decode(cls, received: bytes) -> 'MessageTwo':
        """
        Tries to decode the bytes as an EDHOC MessageTwo object

        :param received: Bytes to decode
        :return: An EDHOC MessageTwo object.
        """

        decoded = super().decode(received)
        ciphertext = decoded[cls.CIPHERTEXT]
        conn_idr = cls.decode_bstr_id(decoded[cls.CONN_ID_R])
        g_y = decoded[cls.G_Y]

        try:
            conn_idi = cls.decode_bstr_id(decoded[cls.CONN_ID_I])
        except IndexError:
            conn_idi = b''

        return cls(g_y, conn_idr, ciphertext, conn_idi)

    @classmethod
    def data_2(cls, g_y: bytes, conn_idr: bytes, corr: Correlation, conn_idi: Optional[bytes] = b'') -> 'CBOR':
        """ Create the data_2 message part. """

        data_2 = [g_y, EdhocMessage.encode_bstr_id(conn_idr)]

        if corr == Correlation.CORR_0 or corr == Correlation.CORR_2:
            data_2.insert(0, EdhocMessage.encode_bstr_id(conn_idi))

        return b''.join(cbor2.dumps(part) for part in data_2)

    def __init__(self, g_y: bytes, conn_idr: bytes, ciphertext: bytes, conn_idi: bytes = b''):
        """
        Creates an EDHOC MessageTwo object.
        """

        self.conn_idr = conn_idr
        self.g_y = g_y
        self.ciphertext = ciphertext
        self.conn_idi = conn_idi

    def encode(self, corr: Correlation) -> bytes:
        """ Encode EDHOC message 2. """

        return b''.join([self.data_2(self.g_y, self.conn_idr, corr, self.conn_idi), cbor2.dumps(self.ciphertext)])

    def __repr__(self) -> str:
        if self.conn_idi != b'':
            output = f'<MessageTwo: [{self.conn_idi}, {EdhocMessage._truncate(self.g_y)}, {self.conn_idr}, ' \
                     f'{self.ciphertext}>'
        else:
            output = f'<MessageTwo: [{EdhocMessage._truncate(self.g_y)}, {self.conn_idr}, {self.ciphertext}>'

        return output
