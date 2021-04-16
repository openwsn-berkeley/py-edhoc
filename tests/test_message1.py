from edhoc.definitions import CipherSuite
from edhoc.messages.message1 import MessageOne


def test_message1_encode(test_vectors):
    msg = MessageOne(
        method_corr=test_vectors["S"]["method_corr"],
        cipher_suites=[CipherSuite.from_id(x) for x in test_vectors["I"]["supported"]],
        selected_cipher=CipherSuite.from_id(test_vectors["I"]["selected"]),
        g_x=test_vectors["I"]["g_x"],
        conn_idi=test_vectors["I"]["conn_id"],
        external_aad=test_vectors["I"]["ad_1"])

    assert msg.encode() == test_vectors["S"]["message_1"]


def test_message1_decode(test_vectors):
    msg = MessageOne.decode(test_vectors['S']['message_1'])

    assert msg.corr == test_vectors["S"]["corr"]
    assert msg.method == test_vectors["S"]["method"]
    assert msg.cipher_suites == [CipherSuite.from_id(x) for x in test_vectors["I"]["supported"]]
    assert msg.selected_cipher.identifier == test_vectors["I"]["selected"]
    assert msg.g_x == test_vectors["I"]["g_x"]
    assert msg.conn_idi == test_vectors['I']['conn_id']
    assert msg.aad1 == test_vectors['I']['ad_1']
