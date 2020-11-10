from typing import List, Union, Optional

from edhoc.definitions import CipherSuite
from edhoc.messages.base import EdhocMessage


class MessageError(EdhocMessage):
    def decode(self, received: bytes):
        _ = super(MessageError, self).decode(received)

    def __init__(self,
                 err_msg: str,
                 conn_id: bytes = b'',
                 suites_r: Optional[Union[List[CipherSuite], CipherSuite]] = None):
        self.err_msg = err_msg
        self.conn_id = conn_id
        self.suites_r = suites_r

    def encode(self):
        pass
