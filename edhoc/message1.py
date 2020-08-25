from typing import List

import cbor2

from edhoc.edhoc import EdhocMessage
from edhoc.suites import BaseCipherSuite


class MessageOne(EdhocMessage):
    @classmethod
    def decode(cls, received: bytes) -> 'MessageOne':

        decoded = []
        while len(received) > 0:
            decoded.append(cbor2.loads(received))
            received = received[received.startswith(cbor2.dumps(decoded[-1])) and len(cbor2.dumps(decoded[-1])):]

        msg = cls(method_corr=decoded[0], cipher_suites=decoded[1], g_x=decoded[2])

        try:
            msg.conn_idi = decoded[3]
        except IndexError:
            pass

        try:
            msg.aad1 = decoded[4]
        except IndexError:
            pass

        return msg

    def __init__(self,
                 method_corr: int,
                 cipher_suites: List[BaseCipherSuite],
                 g_x: bytes,
                 conn_idi: bytes = b'',
                 external_aad: bytes = b''):

        self.method_corr = method_corr
        self.cipher_suites = cipher_suites
        self.g_x = g_x
        self.conn_idi = conn_idi
        self.aad1 = external_aad

    def encode(self) -> bytes:
        """
        Encodes the first EDHOC message, create by the Initiator.
        :return: message 1 encoded as bytes
        """

        if len(self.cipher_suites) > 1:
            suites = self.cipher_suites
            suites.insert(0, self.cipher_suites[0])
        elif len(self.cipher_suites) == 1:
            suites = self.cipher_suites[0]
        else:
            raise ValueError('Cipher suite list must contain at least 1 item.')

        msg = [self.method_corr, suites, self.g_x, self.conn_idi]

        if self.aad1 != b'':
            msg.append(self.aad1)

        return b"".join([cbor2.dumps(msg_part) for msg_part in msg])
