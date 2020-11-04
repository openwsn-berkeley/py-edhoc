from binascii import unhexlify

from edhoc.messages.message1 import MessageOne


def test_message1_encode(message1_tests):
    msg = MessageOne(
        method_corr=message1_tests["S"]["method_corr"],
        cipher_suites=message1_tests["I"]["supported"],
        selected_cipher=message1_tests["I"]["selected"],
        g_x=message1_tests["I"]["g_x"],
        conn_idi=message1_tests["I"]["conn_id"],
        external_aad=message1_tests["I"]["ad1"])

    assert msg.encode() == unhexlify(message1_tests["I"]["message_1"])


def test_message1_decode(message1_tests):
    msg = MessageOne.decode(unhexlify(message1_tests['I']['message_1']))

    assert msg.corr == message1_tests["S"]["corr"]
    assert msg.method == message1_tests["S"]["method"]
    assert msg.cipher_suites == message1_tests["I"]["supported"]
    assert msg.selected_cipher == message1_tests["I"]["selected"]
    assert msg.g_x == message1_tests["I"]["g_x"]
    assert msg.conn_idi == message1_tests['I']['conn_id']
    assert msg.aad1 == message1_tests['I']['ad1']
