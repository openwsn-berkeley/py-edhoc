import cbor2

from edhoc.edhoc import EdhocMessage


class MessageTwo(EdhocMessage):
    @classmethod
    def decode(cls, received: bytes) -> 'MessageTwo':
        pass

    def __init__(self, method_corr: int, ciphertext: bytes, conn_idr: bytes = b"", conn_idi: bytes = b""):
        self.corr = method_corr % 4
        self.ciphertex = ciphertext
        self.conn_idr = conn_idr
        self.conn_idi = conn_idi

    def encode(self) -> bytes:
        msg = []

        if self.corr != 1 and self.corr != 3:
            msg.append(self.conn_idi)

        return b''.join([cbor2.dumps(m) for m in msg])