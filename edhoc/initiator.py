from typing import Optional, List

from orderedset import OrderedSet
from pycose.keys.okp import OKP

from edhoc.edhoc import EdhocRole
from edhoc.message1 import MessageOne
from edhoc.suites import BaseCipherSuite, CipherSuiteMap, CipherSuite


class Initiator(EdhocRole):
    def __init__(self,
                 auth_method: int,
                 corr: int,
                 connection_id: bytes,
                 cred_id_type: int,
                 cred: bytes,
                 suites: Optional[List[BaseCipherSuite]] = None):
        """
        Creates an EDHOC Initiator object.

        :param auth_method: Specifies the authenication method. Valid values are in the range [0 - 3].
        :param corr: Can the underlying transport layer correlate the different EDHOC messages.
        :param connection_id: The initiator connection ID (only used when the transport layer cannot correlate messages)
        :param cred_id_type: sets the credential identifier type (x5t or x5u)
        :param cred: actual credential (CoseKey in case of RPK or CBOR bstr of a certificate)
        :param suites: Additional cipher suites to support (order defines the preference), default is cipher suite 0
        """
        if corr not in {0, 1, 2, 3}:
            raise ValueError(f'{corr} is not a valid correlation mechanism')

        if auth_method not in {0, 1, 2, 3}:
            raise ValueError(f'{auth_method} is not a valid authentication mechanism')

        super().__init__(conn_idi=connection_id,
                         method_corr=4 * auth_method + corr,
                         cred_id_i_type=cred_id_type,
                         cred_i=cred)

        # gets set during negotiation
        self.cipher_suite: Optional[BaseCipherSuite] = None

        # used for cipher suite truncation
        self.max_ciphers = None

        if suites is None:
            self.suites_i = OrderedSet([BaseCipherSuite.CIPHER_SUITE_0])
        else:
            self.suites_i = OrderedSet(suites)
            self.suites_i.add(BaseCipherSuite.CIPHER_SUITE_0)

        ecdh_curve: CipherSuite = CipherSuiteMap[self.suites_i[0].name].value
        self.priv_key: OKP = self._gen_ephemeral_key(ecdh_curve.edhoc_ecdh_curve)

    def truncate_cipher_suites(self, size: int):
        self.max_ciphers = size

    def create_message_one(self):
        return MessageOne(
            method_corr=self.method_corr,
            cipher_suites=list(self.suites_i) if self.max_ciphers is None else list(self.suites_i)[:-self.max_ciphers],
            g_x=self.priv_key.x,
            conn_idi=self.conn_idi,
            external_aad=self._callback_msg1() if self._callback_msg1 is not None else b''
        ).encode()

    def parse_message_two(self):
        pass

    def create_message_three(self):
        pass
