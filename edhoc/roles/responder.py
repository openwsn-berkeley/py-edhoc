from typing import TYPE_CHECKING, List, Callable, Optional

from edhoc.definitions import Correlation, CipherSuite
from edhoc.messages.error import MessageError
from edhoc.messages.message1 import MessageOne
from edhoc.roles.edhoc import EdhocRole

if TYPE_CHECKING:
    pass


class Responder(EdhocRole):
    def __init__(self,
                 corr: Correlation,
                 conn_id: bytes,
                 cred_id_type,
                 cred: bytes,
                 supported_ciphers: List[CipherSuite],
                 aad1_cb: Optional[Callable] = None):
        super(Responder, self).__init__(corr, conn_id, cred_id_type, cred, supported_ciphers)

        self.aad1_cb = aad1_cb

        # epher
        self._ephemeral_key = None

    def create_message_two(self, message_one: bytes) -> bytes:
        """
        Decodes an incoming EDHOC message 1 and creates and EDHOC message 2 or error message based on the content
        of message 1.

        :param message_one: Bytes representing an EDHOC message 1.
        :returns: Bytes of an EDHOC message 2 or an EDHOC error message.
        """

        msg_1 = MessageOne.decode(message_one)

        if not self._verify_cipher_selection(msg_1.selected_cipher, msg_1.cipher_suites):
            return MessageError().encode()

        if msg_1.aad1 != b'' and self.aad1_cb is not None:
            self.aad1_cb(msg_1.aad1)

    def _verify_cipher_selection(self, selected: CipherSuite, supported: List[CipherSuite]) -> bool:
        """
        Checks if the selected cipher suite is supported and that no prior cipher suites in the Initiator's list of
        supported ciphers is supported by the Responder.

        :param selected: the cipher suite selected by the Initiator
        :param supported: the list of cipher suites supported by the Initiator
        :return:
        """
        if selected not in self.supported_ciphers:
            return False

        for sc in supported:
            if sc in self.supported_ciphers and sc != selected:
                return False
            elif sc in self.supported_ciphers and sc == selected:
                return True
            else:
                continue

        return True

