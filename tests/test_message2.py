from edhoc.messages.message2 import MessageTwo


def test_message2_encode(test_vectors):
    msg = MessageTwo(
        test_vectors['R']['g_y'],
        test_vectors['R']['conn_id'],
        test_vectors['R']['ciphertext_2'],
        conn_idi=test_vectors['I']['conn_id'])

    suite(msg, test_vectors)


def test_message2_decode(test_vectors):
    msg = MessageTwo.decode(test_vectors['R']['message_2'])

    suite(msg, test_vectors)


def suite(msg, test_vectors):
    # always included
    assert msg.conn_idr == test_vectors['R']['conn_id']

    # only included when using specific correlation values
    # assert msg.conn_idi == test_vectors['I']['conn_id']
    assert msg.g_y == test_vectors['R']['g_y']
    assert msg.ciphertext == test_vectors['R']['ciphertext_2']

    # assert msg.encode() == test_vectors['R']['message_2']
