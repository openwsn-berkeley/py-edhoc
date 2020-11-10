from cose import OKP

from edhoc.definitions import CipherSuite
from edhoc.messages import MessageTwo, MessageOne, MessageThree
from cose.attributes.algorithms import config as config_cose, CoseEllipticCurves


def test_initiator_message1(initiator, test_vectors):
    assert initiator.corr == test_vectors['S']['corr']
    assert initiator.method == test_vectors['S']['method']
    assert initiator.ephemeral_key.d == test_vectors['I']['x']
    assert initiator.ephemeral_key.x == test_vectors['I']['g_x']
    assert initiator.create_message_one() == test_vectors['I']['message_1']


def test_initiator_message3(initiator, test_vectors):
    initiator.msg_1 = MessageOne.decode(test_vectors['I']['message_1'])
    initiator.msg_2 = MessageTwo.decode(test_vectors['R']['message_2'])

    crv = CoseEllipticCurves(CipherSuite(initiator._selected_cipher).dh_curve)
    hash_func = config_cose(CipherSuite(initiator._selected_cipher).hash).hash

    assert initiator.data_2 == test_vectors['R']['data_2']
    assert initiator._th2_input == test_vectors['R']['input_th_2']
    assert initiator._prk2e == test_vectors['R']['prk_2e']
    assert initiator._prk3e2m == test_vectors['R']['prk_3e2m']
    assert initiator.transcript(hash_func, initiator._th2_input) == test_vectors['R']['th_2']

    assert initiator._decrypt(initiator.msg_2.ciphertext) == test_vectors['R']['p_2e']

    assert initiator.shared_secret(initiator.ephemeral_key, OKP(x=initiator.g_y, crv=crv)) == test_vectors['S']['g_xy']
    assert initiator.data_3 == test_vectors['I']['data_3']
    assert initiator._th3_input == test_vectors['I']['input_th_3']
    assert initiator.transcript(hash_func, initiator._th3_input) == test_vectors['I']['th_3']
    assert initiator.cred_id == test_vectors['I']['id_cred']
    assert initiator._prk4x3m == test_vectors['I']['prk_4x3m']
    assert initiator._external_aad(initiator._th3_input, initiator.aad3_cb) == test_vectors['I']['eaad_3m']
    assert initiator._hkdf3(16, 'K_3m', initiator._prk4x3m) == test_vectors['I']['k_3m']
    assert initiator._hkdf3(13, 'IV_3m', initiator._prk4x3m) == test_vectors['I']['iv_3m']
    assert initiator._mac(
        initiator._hkdf3,
        'K_3m',
        16,
        'IV_3m',
        13,
        initiator._th3_input,
        initiator._prk4x3m,
        initiator.aad2_cb) == test_vectors['I']['mac3']
    assert initiator.signature_or_mac3(test_vectors['I']['mac3']) == test_vectors['I']['sign_or_mac3']
    assert initiator._p_3ae == test_vectors['I']['p_3ae']
    assert initiator._hkdf3(16, 'K_3ae', initiator._prk3e2m) == test_vectors['I']['k_3ae']
    assert initiator._hkdf3(13, 'IV_3ae', initiator._prk3e2m) == test_vectors['I']['iv_3ae']
    assert initiator.ciphertext_3 == test_vectors['I']['ciphertext_3']

    assert initiator.create_message_three(test_vectors['R']['message_2']) == test_vectors['I']['message_3']


def test_initiator_finalize(initiator, test_vectors):
    initiator.msg_1 = MessageOne.decode(initiator.create_message_one())
    initiator.msg_2 = MessageTwo.decode(test_vectors['R']['message_2'])
    initiator.msg_3 = MessageThree.decode(initiator.create_message_three(test_vectors['R']['message_2']))

    c_i, c_r, app_aead, app_hash = initiator.finalize()

    assert c_i == test_vectors['I']['conn_id']
    assert c_r == test_vectors['R']['conn_id']
    assert app_aead == CipherSuite(test_vectors['I']['selected']).app_aead.id
    assert app_hash == CipherSuite(test_vectors['I']['selected']).app_hash.id
