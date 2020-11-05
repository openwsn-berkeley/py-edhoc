from abc import ABCMeta, abstractmethod
from typing import Union

import cbor2


class EdhocMessage(metaclass=ABCMeta):
    """ Abstract base class for all EDHOC messages. """

    @classmethod
    def decode(cls, received: bytes) -> list:
        """
        Decode a received EDHOC message.

        :param received: Received bytes of an EDHOC message.
        :return: a decode EDHOC message
        """

        decoded = []

        while len(received) > 0:
            decoded += [cbor2.loads(received)]
            received = received[received.startswith(cbor2.dumps(decoded[-1])) and len(cbor2.dumps(decoded[-1])):]
        return decoded

    @abstractmethod
    def encode(self):
        """ Encodes an EDHOC message as bytes, ready to be sent over reliable transport. """

        raise NotImplementedError

    @staticmethod
    def encode_bstr_id(conn_id: bytes) -> Union[int, bytes]:
        if len(conn_id) == 1:
            return int.from_bytes(conn_id, byteorder='big') - 24
        else:
            return conn_id

    @staticmethod
    def decode_bstr_id(conn_id: int) -> bytes:
        return int(conn_id + 24).to_bytes(1, byteorder="big")

    @classmethod
    def _truncate(cls, payload: bytes):
        return f'{payload[:5]} ... ({len(payload)} bytes)'
