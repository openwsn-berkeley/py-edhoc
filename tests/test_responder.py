import os
from binascii import unhexlify

import pytest

from edhoc.responder import Responder
from edhoc.suites import BaseCipherSuite
from pycose.keys.okp import OKP


@pytest.mark.parametrize("d, g_x, g_y, shared",
                         [
                             (unhexlify("fd8cd877c9ea386e6af34ff7e606c4b64ca831c8ba33134fd4cd7167cabaecda"),
                              unhexlify("71a3d599c21da18902a1aea810b2b6382ccd8d5f9bf0195281754c5ebcaf301e"),
                              unhexlify("898ff79a02067a16ea1eccb90fa52246f5aa4dd6ec076bba0259d904b7ec8b0c"),
                              unhexlify("2bb7fa6e135bc335d022d634cbfb14b3f582f3e2e3afb2b3150491495c61782b"))
                         ], ids=["compute_ecdh_1"])
def test_responder_ecdh(d, g_x, g_y, shared):
    private = OKP(d=d, x=g_x)
    public = OKP(x=g_y)

    rsp = Responder(connection_id=os.urandom(5))
    rsp.pub_key = public
    rsp.priv_key = private
    rsp.cipher_suite = BaseCipherSuite.CIPHER_SUITE_0
    assert rsp._compute_ecdh() == shared
