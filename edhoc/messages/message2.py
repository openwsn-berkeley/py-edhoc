from typing import Optional, Union, List

import cbor2

from edhoc.messages.base import EdhocMessage


class MessageTwo(EdhocMessage):
    CIPHERTEXT = -1
    DATA_2 = -2

    @classmethod
    def decode(cls, received: bytes) -> 'EdhocMessage':
        """
        Tries to decode the bytes as an EDHOC MessageTwo object
        :param received: Bytes to decode
        :return: An EDHOC MessageTwo object.
        """

        decoded = super().decode(received)
        ciphertext = decoded[cls.CIPHERTEXT]
        data_2 = decoded[:cls.DATA_2]

        return cls(data_2=data_2, ciphertext=ciphertext)

    def __init__(self, data_2: List[Union[bytes, int]], ciphertext: bytes):
        """
        Creates an EDHOC MessageTwo object.

        :param data_2: An optional Initiator connection id and, the responder's ephemeral public key and connection id.
        :param ciphertext: Ciphertext.
        """

        self.data_2 = data_2
        self.ciphertext = ciphertext

    def encode(self):
        pass
