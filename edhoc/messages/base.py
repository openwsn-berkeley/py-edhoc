from abc import ABCMeta, abstractmethod
from typing import Union
from edhoc.definitions import Correlation
import warnings
from io import BytesIO

import cbor2


class EdhocMessage(metaclass=ABCMeta):
    """ Abstract base class for all EDHOC messages. """

    @classmethod
    def decode(cls, received: BytesIO) -> list:
        """
        Decode a received EDHOC message.

        :param received: Received bytes of an EDHOC message.
        :return: a decode EDHOC message
        """

        if isinstance(received, bytes):
            warnings.warn("%s received bytes for decoding")
            received = BytesIO(received)

        decoded = []

        total_length = len(received.getvalue())
        while received.tell() < total_length:
            decoded.append(cbor2.load(received))
        return decoded

    @abstractmethod
    def encode(self, corr: Correlation):
        """ Encodes an EDHOC message as bytes, ready to be sent over reliable transport. """

        raise NotImplementedError

    @classmethod
    def _truncate(cls, payload: bytes):
        return f'{payload[:5]} ... ({len(payload)} bytes)'
