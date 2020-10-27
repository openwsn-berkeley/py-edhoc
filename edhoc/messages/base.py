from abc import ABCMeta, abstractmethod


class EdhocMessage(metaclass=ABCMeta):
    """ Abstract base class for all EDHOC messages. """

    @classmethod
    @abstractmethod
    def decode(cls, received: bytes, corr: int) -> 'EdhocMessage':
        """
        Decode a received EDHOC message.
        :param received: Received bytes of an EDHOC message.
        :param corr: Determines the correlation capabilities of the transport layer
        :return: a decode EDHOC message
        """

        raise NotImplementedError

    @abstractmethod
    def encode(self):
        """
        Encodes an EDHOC message as bytes, ready to be sent over reliable transport.
        """
        raise NotImplementedError
