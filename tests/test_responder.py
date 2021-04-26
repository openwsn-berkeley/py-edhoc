import warnings

import cbor2
from cose.headers import KID
from cose.keys import OKPKey

from edhoc.definitions import CipherSuite
from edhoc.messages import MessageThree, MessageTwo, EdhocMessage
from edhoc.messages.message1 import MessageOne

class NoRemoteKey(UserWarning):
    def __str__(self):
        return "Skipping verification for lack of auth key"

def test_responder_message2(responder, test_vectors):
    responder.msg_1 = MessageOne.decode(test_vectors['S']['message_1'])

    hash_func = CipherSuite.from_id(responder.msg_1.selected_cipher).hash.hash_cls
    crv = CipherSuite.from_id(responder.msg_1.selected_cipher).dh_curve

    assert responder.shared_secret(responder.ephemeral_key, OKPKey(x=responder.g_x, crv=crv)) == test_vectors['S'][
        'g_xy']
    assert responder._prk2e == test_vectors['S']['prk_2e']
    assert responder._prk3e2m == test_vectors['S']['prk_3e2m']
    assert responder.data_2 == test_vectors['S']['data_2']
    assert responder._th2_input == test_vectors['S']['input_th_2']
    assert responder.cred_id == cbor2.loads(test_vectors['R']['cred_id'])
    assert responder.transcript(hash_func, responder._th2_input) == test_vectors['S']['th_2']
    assert responder._hkdf2(16, 'K_2m', prk=responder._prk3e2m) == test_vectors['S']['k_2m']
    assert responder._hkdf2(13, 'IV_2m', prk=responder._prk3e2m) == test_vectors['S']['iv_2m']
    assert responder._mac(
        responder.cred_idr,
        responder.cred,
        responder._hkdf2,
        'K_2m',
        16,
        'IV_2m',
        13,
        responder._th2_input,
        responder._prk3e2m,
        responder.aad2_cb) == test_vectors['S']['mac_2']
    assert responder.signature_or_mac2(test_vectors['S']['mac_2']) == test_vectors['S']['signature_2']
    assert responder._p_2e == test_vectors['S']['p_2e']
    assert responder._hkdf2(len(responder._p_2e), 'KEYSTREAM_2', prk=responder._prk2e) == test_vectors['S'][
        'keystream_2']
    assert responder.ciphertext_2 == test_vectors['S']['ciphertext_2']

    assert responder.create_message_two(test_vectors['S']['message_1']) == test_vectors['S']['message_2']


def test_responder_finalize(responder, test_vectors):
    responder.msg_1 = MessageOne.decode(test_vectors['S']['message_1'])
    responder.msg_2 = MessageTwo.decode(responder.create_message_two(test_vectors['S']['message_1']))
    responder.msg_3 = MessageThree.decode(test_vectors['S']['message_3'])

    decoded = EdhocMessage.decode(responder._decrypt(responder.msg_3.ciphertext))
    if KID.identifier in cbor2.loads(test_vectors['I']['cred_id']):
        assert decoded[0] == EdhocMessage.encode_bstr_id(cbor2.loads(test_vectors['I']['cred_id'])[KID.identifier])
    else:
        assert decoded[0] == cbor2.loads(test_vectors['I']['cred_id'])
    assert decoded[1] == test_vectors['S']['signature_3']

    if getattr(responder, 'remote_authkey', None) is None:
        warnings.warn(NoRemoteKey())
        return
    c_i, c_r, app_aead, app_hash = responder.finalize(test_vectors['S']['message_3'])

    assert c_i == test_vectors['I']['conn_id']
    assert c_r == test_vectors['R']['conn_id']
    assert app_aead == CipherSuite.from_id(test_vectors['I']['selected']).app_aead.identifier
    assert app_hash == CipherSuite.from_id(test_vectors['I']['selected']).app_hash.identifier
