from cose.headers import KID
from cose.keys import OKPKey

from edhoc.definitions import CipherSuite
from edhoc.messages import MessageThree, MessageTwo, EdhocMessage
from edhoc.messages.message1 import MessageOne


def test_responder_message2(responder, test_vectors):
    responder.msg_1 = MessageOne.decode(test_vectors['I']['message_1'])

    hash_func = CipherSuite.from_id(responder.msg_1.selected_cipher).hash.hash_cls
    crv = CipherSuite.from_id(responder.msg_1.selected_cipher).dh_curve

    assert responder.shared_secret(responder.ephemeral_key, OKPKey(x=responder.g_x, crv=crv)) == test_vectors['S'][
        'g_xy']
    assert responder._prk2e == test_vectors['R']['prk_2e']
    assert responder._prk3e2m == test_vectors['R']['prk_3e2m']
    assert responder.data_2 == test_vectors['R']['data_2']
    assert responder._th2_input == test_vectors['R']['input_th_2']
    assert responder.cred_id == test_vectors['R']['id_cred']
    assert responder.transcript(hash_func, responder._th2_input) == test_vectors['R']['th_2']
    assert responder._external_aad(responder._th2_input, responder.aad2_cb) == test_vectors['R']['eaad_2m']
    assert responder._hkdf2(16, 'K_2m', prk=responder._prk3e2m) == test_vectors['R']['k_2m']
    assert responder._hkdf2(13, 'IV_2m', prk=responder._prk3e2m) == test_vectors['R']['iv_2m']
    assert responder._mac(
        responder._hkdf2,
        'K_2m',
        16,
        'IV_2m',
        13,
        responder._th2_input,
        responder._prk3e2m,
        responder.aad2_cb) == test_vectors['R']['mac2']
    assert responder.signature_or_mac2(test_vectors['R']['mac2']) == test_vectors['R']['sign_or_mac2']
    assert responder._p_2e == test_vectors['R']['p_2e']
    assert responder._hkdf2(len(responder._p_2e), 'K_2e', prk=responder._prk2e) == test_vectors['R']['k_2e']
    assert responder.ciphertext_2 == test_vectors['R']['ciphertext_2']

    assert responder.create_message_two(test_vectors['I']['message_1']) == test_vectors['R']['message_2']


def test_responder_finalize(responder, test_vectors):
    responder.msg_1 = MessageOne.decode(test_vectors['I']['message_1'])
    responder.msg_2 = MessageTwo.decode(responder.create_message_two(test_vectors['I']['message_1']))
    responder.msg_3 = MessageThree.decode(test_vectors['I']['message_3'])

    decoded = EdhocMessage.decode(responder._decrypt(responder.msg_3.ciphertext))
    if KID.identifier in test_vectors['I']['id_cred']:
        assert decoded[0] == EdhocMessage.encode_bstr_id(test_vectors['I']['id_cred'][KID.identifier])
    else:
        assert decoded[0] == test_vectors['I']['id_cred']
    assert decoded[1] == test_vectors['I']['sign_or_mac3']

    c_i, c_r, app_aead, app_hash = responder.finalize(test_vectors['I']['message_3'])

    assert c_i == test_vectors['I']['conn_id']
    assert c_r == test_vectors['R']['conn_id']
    assert app_aead == CipherSuite.from_id(test_vectors['I']['selected']).app_aead.identifier
    assert app_hash == CipherSuite.from_id(test_vectors['I']['selected']).app_hash.identifier
