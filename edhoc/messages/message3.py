from typing import Optional

import cbor2

from edhoc.definitions import Correlation
from edhoc.messages.base import EdhocMessage


class MessageThree(EdhocMessage):
    @classmethod
    def decode(cls, received) -> 'MessageThree':
        """
        Tries to decode the bytes as an EDHOC MessageThree object

        :param received:
        :return:
        """

        decoded = super().decode(received)
        (ciphertext,) = decoded

        return cls(ciphertext)

    def __init__(self, ciphertext: bytes):
        """
        Creates an EDHOC MessageThree object.
        """

        self.ciphertext = ciphertext

    def encode(self):
        """ Encode EDHOC message 3. """
        return cbor2.dumps(self.ciphertext)
