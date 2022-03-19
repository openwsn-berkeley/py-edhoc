from typing import Optional

import cbor2

from edhoc.definitions import Correlation
from edhoc.messages.base import EdhocMessage


class MessageThree(EdhocMessage):
    CIPHERTEXT = -1
    CONN_ID_R = -2

    @classmethod
    def decode(cls, received) -> 'MessageThree':
        """
        Tries to decode the bytes as an EDHOC MessageThree object

        :param received:
        :return:
        """

        decoded = super().decode(received)
        ciphertext = decoded[cls.CIPHERTEXT]

        try:
            conn_idr = cls.decode_bstr_id(decoded[cls.CONN_ID_R])
        except IndexError:
            conn_idr = b''

        return cls(ciphertext, conn_idr)

    @classmethod
    def data_3(cls, corr: Correlation, conn_idr: Optional[bytes] = b'') -> bytes:
        """ Create the data_2 message part. """

        if corr == Correlation.CORR_1 or corr == Correlation.CORR_2:
            return EdhocMessage.encode_bstr_id(conn_idr)
        else:
            return b''

    def __init__(self, ciphertext: bytes, conn_idr: bytes):
        """
        Creates an EDHOC MessageThree object.
        """

        self.ciphertext = ciphertext
        self.conn_idr = conn_idr

    def encode(self, corr: Correlation):
        """ Encode EDHOC message 3. """
        data_3 = cbor2.dumps(self.data_3(corr, self.conn_idr))
        return b''.join([data_3, cbor2.dumps(self.ciphertext)])
