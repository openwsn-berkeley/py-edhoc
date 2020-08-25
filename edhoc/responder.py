from typing import Union, Optional, List

import cbor2

from edhoc.edhoc import EdhocRole
from edhoc.message1 import MessageOne
from edhoc.message2 import MessageTwo
from edhoc.suites import BaseCipherSuite, CipherSuiteMap, CipherSuite
from pycose.keys.okp import OKP


class Responder(EdhocRole):
    def __init__(self, connection_id: bytes, suites_r: Optional[List[BaseCipherSuite]] = None):
        super().__init__(conn_idr=connection_id)

        if suites_r is None:
            self.suites_r = {BaseCipherSuite.CIPHER_SUITE_0}
        else:
            self.suites_r = set(suites_r)
            self.suites_r.add(BaseCipherSuite.CIPHER_SUITE_0)

    def parse_message_one(self, received: bytes) -> bool:
        """
        Parses the first EDHOC message, received from the Initiator.
        :param received: the received initial EDHOC message as a byte string
        :return: True if parsing was successful, otherwise False
        """

        try:
            msg1 = MessageOne.decode(received)
        except (cbor2.CBORDecodeError, cbor2.CBORDecodeEOF):
            return False

        self.method_corr = msg1.method_corr

        if not self._pick_cipher_suite(msg1.cipher_suites):
            return False

        self.pub_key = OKP(x=msg1.g_x)
        self.conn_idi = msg1.conn_idi
        self.aad1 = msg1.aad1

        return True

    def _pick_cipher_suite(self, received_ciphers: Union[List[int], int]) -> bool:

        if isinstance(received_ciphers, int) and received_ciphers in self.suites_r:
            self.cipher_suite = BaseCipherSuite(received_ciphers)

        elif isinstance(received_ciphers, list):
            if received_ciphers[0] in self.suites_r:
                self.cipher_suite = BaseCipherSuite(received_ciphers[0])
            else:
                # responder does not support the selected cipher suite
                return False
        else:
            TypeError("Conveyed cipher suite must be an integer or a list of integers.")

        return True

    def create_message_two(self) -> bytes:
        """
        Creates the second EDHOC message.
        :return: byte string representing EHDOC MESSAGE 2
        """
        cipher_suite_info: CipherSuite = CipherSuiteMap[self.cipher_suite.name].value
        self.priv_key = self._gen_ephemeral_key(cipher_suite_info.edhoc_ecdh_curve)



        return MessageTwo(
            method_corr=self.method_corr,
            ciphertext=ciphertext,
            conn_idr=self.conn_idr,
            conn_idi=self.conn_idi).encode()
