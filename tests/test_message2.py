from edhoc.messages.message2 import MessageTwo


def test_message2_encode(test_vectors):
    msg = MessageTwo(
        g_y=test_vectors['R']['g_y'],
        conn_idr=test_vectors['R']['conn_id'],
        ciphertext=test_vectors['S']['ciphertext_2'],
        conn_idi=test_vectors['R']['conn_id'])

    suite(msg, test_vectors)


def test_message2_decode(test_vectors):
    msg = MessageTwo.decode(test_vectors['S']['message_2'])

    suite(msg, test_vectors)


def suite(msg, test_vectors):
    # always included
    assert msg.conn_idr == test_vectors['R']['conn_id']

    if test_vectors['S']['corr'] == 0 or test_vectors['S']['corr'] == 2:
        assert msg.conn_idi == test_vectors['I']['conn_id']

    assert msg.g_y == test_vectors['R']['g_y']
    assert msg.ciphertext == test_vectors['S']['ciphertext_2']

    assert msg.encode(test_vectors['S']['corr']) == test_vectors['S']['message_2']
