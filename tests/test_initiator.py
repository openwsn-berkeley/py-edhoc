import warnings

import cbor2
from cose.keys import OKPKey

from edhoc.definitions import CipherSuite
from edhoc.messages import MessageTwo, MessageOne, MessageThree

class NoRemoteKey(UserWarning):
    def __str__(self):
        return "Skipping verification for lack of auth key"

def test_initiator_message1(initiator, test_vectors):
    assert initiator.corr == test_vectors['S']['corr']
    assert initiator.method == test_vectors['S']['method']
    assert initiator.ephemeral_key.d == test_vectors['I']['x']
    assert initiator.ephemeral_key.x == test_vectors['I']['g_x']
    assert initiator.create_message_one() == test_vectors['S']['message_1']


def test_initiator_message3(initiator, test_vectors):
    initiator.msg_1 = MessageOne.decode(test_vectors['S']['message_1'])
    initiator.msg_2 = MessageTwo.decode(test_vectors['S']['message_2'])

    crv = CipherSuite.from_id(initiator._selected_cipher).dh_curve
    hash_func = CipherSuite.from_id(initiator._selected_cipher).hash.hash_cls

    assert initiator.data_2 == test_vectors['S']['data_2']
    assert initiator._th2_input == test_vectors['S']['input_th_2']
    assert initiator._prk2e == test_vectors['S']['prk_2e']
    assert initiator._prk3e2m == test_vectors['S']['prk_3e2m']
    assert initiator.transcript(hash_func, initiator._th2_input) == test_vectors['S']['th_2']

    assert initiator._decrypt(initiator.msg_2.ciphertext) == test_vectors['S']['p_2e']

    assert initiator.shared_secret(initiator.ephemeral_key, OKPKey(x=initiator.g_y, crv=crv)) == test_vectors['S'][
        'g_xy']
    assert initiator.data_3 == test_vectors['S']['data_3']
    assert initiator._th3_input == test_vectors['S']['input_th_3']
    assert initiator.transcript(hash_func, initiator._th3_input) == test_vectors['S']['th_3']
    assert initiator.cred_id == cbor2.loads(test_vectors['I']['cred_id'])
    assert initiator._prk4x3m == test_vectors['S']['prk_4x3m']
    assert initiator._hkdf3(16, 'K_3m', initiator._prk4x3m) == test_vectors['S']['k_3m']
    assert initiator._hkdf3(13, 'IV_3m', initiator._prk4x3m) == test_vectors['S']['iv_3m']
    assert initiator._mac(
        initiator.cred_idi,
        initiator.cred,
        initiator._hkdf3,
        'K_3m',
        16,
        'IV_3m',
        13,
        initiator._th3_input,
        initiator._prk4x3m,
        initiator.aad2_cb) == test_vectors['S']['mac_3']
    assert initiator.signature_or_mac3(test_vectors['S']['mac_3']) == test_vectors['S']['signature_3']
    assert initiator._p_3ae == test_vectors['S']['p_3ae']
    assert initiator._hkdf3(16, 'K_3ae', initiator._prk3e2m) == test_vectors['S']['k_3ae']
    assert initiator._hkdf3(13, 'IV_3ae', initiator._prk3e2m) == test_vectors['S']['iv_3ae']
    assert initiator.ciphertext_3 == test_vectors['S']['ciphertext_3']

    if initiator.remote_authkey is None:
        warnings.warn(NoRemoteKey())
        return
    assert initiator.create_message_three(test_vectors['S']['message_2']) == test_vectors['S']['message_3']


def test_initiator_finalize(initiator, test_vectors):
    initiator.msg_1 = MessageOne.decode(initiator.create_message_one())
    initiator.msg_2 = MessageTwo.decode(test_vectors['S']['message_2'])
    if getattr(initiator, 'remote_authkey', None) is None:
        warnings.warn(NoRemoteKey())
        return

    initiator.msg_3 = MessageThree.decode(initiator.create_message_three(test_vectors['S']['message_2']))

    c_i, c_r, app_aead, app_hash = initiator.finalize()

    assert c_i == test_vectors['I']['conn_id']
    assert c_r == test_vectors['R']['conn_id']
    assert app_aead == CipherSuite.from_id(test_vectors['I']['selected']).app_aead.identifier
    assert app_hash == CipherSuite.from_id(test_vectors['I']['selected']).app_hash.identifier
