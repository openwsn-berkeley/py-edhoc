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

    def __repr__(self):
        return "<%s: %s on connection ID %r%s>" % (
                type(self).__name__,
                self.err_msg,
                self.conn_id,
                " with suites %r" % self.suites_r if self.suites_r else ""
                )

    def encode(self):
        raise NotImplementedError("Can not encode %r yet" % self)
