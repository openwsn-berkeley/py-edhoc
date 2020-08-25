import os
from binascii import unhexlify

import pytest

from edhoc.initiator import Initiator
from pycose.keys.okp import OKP


@pytest.mark.parametrize("method_corr, suites, g_x, connection_id, aad, output",
                         [
                             (1, 0, unhexlify("898ff79a02067a16ea1eccb90fa52246f5aa4dd6ec076bba0259d904b7ec8b0c"), b'',
                              b'',
                              unhexlify("01005820898ff79a02067a16ea1eccb90fa52246f5aa4dd6ec076bba0259d904b7ec8b0c40"))
                         ], ids=["initiator_create_message_1"])
def test_initiator_message_one(method_corr, suites, g_x, connection_id, aad, output):
    itr = Initiator(auth_method=0, corr=method_corr, connection_id=connection_id)
    itr.priv_key = OKP(x=g_x)
    assert output == itr.create_message_one()


@pytest.mark.parametrize("input1, input2, output",
                         [
                             (unhexlify('01005820898ff79a02067a16ea1eccb90fa52246f5aa4dd6ec076bba0259d904b7ec8b0c40'),
                              unhexlify('582071a3d599c21da18902a1aea810b2b6382ccd8d5f9bf0195281754c5ebcaf301e13'),
                              unhexlify('b0dc6c1ba0bae6e2888610fa0b27bfc52e311a47b9cafb609de4f6a1760d6cf7'))
                         ], ids=["transcript_computation_1"])
def test_initiator_message_transcript(input1, input2, output):
    itr = Initiator(auth_method=0, corr=0, connection_id=os.urandom(12))
    itr.cipher_suite = 0
    assert itr._compute_transcript(msg_parts=[input1, input2]) == output
