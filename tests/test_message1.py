from binascii import unhexlify

from pytest import mark

from edhoc.message1 import MessageOne
from edhoc.suites import BaseCipherSuite


@mark.parametrize("method_corr, suites, g_x, connection_id, aad, output",
                  [
                      (1,
                       [BaseCipherSuite.CIPHER_SUITE_0],
                       unhexlify("898ff79a02067a16ea1eccb90fa52246f5aa4dd6ec076bba0259d904b7ec8b0c"),
                       b'',
                       b'',
                       unhexlify("01005820898ff79a02067a16ea1eccb90fa52246f5aa4dd6ec076bba0259d904b7ec8b0c40"))
                  ], ids=["message_1_encoding"])
def test_message1_encode(method_corr, suites, g_x, connection_id, aad, output):
    msg = MessageOne(method_corr, suites, g_x, connection_id, aad)
    assert msg.encode() == output


@mark.parametrize("received, method_corr, suites, g_x, connection_id, aad",
                  [
                      (unhexlify("01005820898ff79a02067a16ea1eccb90fa52246f5aa4dd6ec076bba0259d904b7ec8b0c40"),
                       1,
                       BaseCipherSuite.CIPHER_SUITE_0,
                       unhexlify("898ff79a02067a16ea1eccb90fa52246f5aa4dd6ec076bba0259d904b7ec8b0c"),
                       b'',
                       b'')
                  ], ids=["message_1_decoding"])
def test_message1_decode(received, method_corr, suites, g_x, connection_id, aad):
    msg_one = MessageOne.decode(received)
    assert msg_one.method_corr == method_corr
    assert msg_one.cipher_suites == suites
    assert msg_one.g_x == g_x
    assert msg_one.conn_idi == connection_id
    assert msg_one.aad1 == aad
