from abc import ABCMeta, abstractmethod

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
        """
        Encodes an EDHOC message as bytes, ready to be sent over reliable transport.
        """
        raise NotImplementedError

    @classmethod
    def _truncate(cls, payload: bytes):
        return f'{payload[:5]} ... ({len(payload)} bytes)'
