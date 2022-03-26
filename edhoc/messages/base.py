from abc import ABCMeta, abstractmethod
from typing import Union
from edhoc.definitions import Correlation
import warnings
from io import BytesIO

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

        received = BytesIO(received)

        decoded = []

        total_length = len(received.getvalue())
        while received.tell() < total_length:
            decoded.append(cbor2.load(received))
        return decoded

    @abstractmethod
    def encode(self):
        """ Encodes an EDHOC message as bytes, ready to be sent over reliable transport. """

        raise NotImplementedError

    @classmethod
    def _truncate(cls, payload: bytes):
        return f'{payload[:5]} ... ({len(payload)} bytes)'
