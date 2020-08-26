from typing import Union, TYPE_CHECKING

import cbor2

from edhoc.edhoc import EdhocMessage
from pycose import Enc0Message
from pycose.cosebase import HeaderKeys
from pycose.x509 import X5T, X5U


class MessageTwo(EdhocMessage):
    @classmethod
    def decode(cls, received: bytes) -> 'MessageTwo':
        pass

    def __init__(self,
                 method_corr: int,
                 g_y: bytes,
                 cred_id_r: Union[X5T, X5U],
                 cred_r: bytes,
                 th_2: bytes,
                 conn_idr: bytes = b"",
                 conn_idi: bytes = b"",
                 external_aad: bytes = b''):

        self.corr = method_corr % 4
        self.conn_idr = conn_idr
        self.conn_idi = conn_idi
        self.cred_r = cred_r
        self.cred_id_r = cred_id_r
        self.th_2 = th_2
        self.g_y = g_y
        self.aad2 = external_aad

    def _create_data_2(self) -> bytes:
        data_2 = []

        if self.conn_idi != b'':
            data_2.append(self.conn_idi)

        data_2.append(self.g_y)
        data_2.append(self.conn_idr)

        return b''.join([cbor2.dumps(d) for d in data_2])

    def _create_ciphertext(self):
        phdr = {}

        if isinstance(self.cred_id_r, X5U):
            phdr[HeaderKeys.X5_T] = self.cred_id_r.encode()
        elif isinstance(self.cred_id_r, X5T):
            phdr[HeaderKeys.X5_U] = self.cred_id_r.encode()
        else:
            raise TypeError("Invalid credential id type")

        aad = [self.th_2, self.cred_r]
        if self.aad2 != b'':
            aad.append(self.aad2)

        aad = b''.join([cbor2.dumps(ad) for ad in aad])

        cose_encrypt0 = Enc0Message(phdr=phdr, external_aad=aad)

    def encode(self) -> bytes:
        msg = []

        if self.corr != 1 and self.corr != 3:
            msg.append(self.conn_idi)

        return b''.join([cbor2.dumps(m) for m in msg])
