from binascii import unhexlify

import cbor2
from pytest import mark

from edhoc.initiator import Initiator
from edhoc.responder import Responder
from edhoc.suites import BaseCipherSuite as base
from pycose.cosebase import HeaderKeys

certificate = "47624dc9cdc6824b2a4c52e95ec9d6b0534b71c2b49e4bf9031500cee6869979c297bb5a8b381e98db714108415e5c50db" \
              "78974c271579b01633a3ef6271be5c225eb28f9cf6180b5a6af31e80209a085cfbf95f3fdcf9b18b693d6c0e0d0ffb8e3f9a32" \
              "a50859ecd0bfcff2c218"

messages = [
    unhexlify("01005820898ff79a02067a16ea1eccb90fa52246f5aa4dd6ec076bba0259d904b7ec8b0c40"),
]


@mark.parametrize(
    "corr, auth_method, conn_id_i, conn_id_r, suites, cred_i, cred_r, cred_id_i_type, cred_id_r_type, msgs",
    [
        (1,
         0,
         b'',
         b'13',
         [base.CIPHER_SUITE_0, base.CIPHER_SUITE_1, base.CIPHER_SUITE_2, base.CIPHER_SUITE_3],
         cbor2.dumps(certificate),
         cbor2.dumps(certificate),
         HeaderKeys.X5_T,
         HeaderKeys.X5_T,
         messages)
    ])
def test_edhoc_exchange(
        corr, auth_method, conn_id_i, conn_id_r, suites, cred_i, cred_r, cred_id_i_type, cred_id_r_type, msgs):
    # initiator
    itr = Initiator(
        auth_method=auth_method,
        corr=corr,
        connection_id=conn_id_i,
        suites=suites,
        cred=cred_i,
        cred_id_type=cred_id_i_type)

    assert msgs[0] == itr.create_message_one()

    # responder
    rsp = Responder(
        connection_id=conn_id_r,
        cred=cred_r,
        cred_id_type=cred_id_r_type)
