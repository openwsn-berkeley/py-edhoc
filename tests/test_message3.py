from edhoc.messages import MessageThree


def test_message3_encode(test_vectors):
    msg = MessageThree(
        test_vectors["I"]['ciphertext_3'],
        test_vectors["R"]['conn_id'])

    suite(msg, test_vectors)


def test_message3_decode(test_vectors):
    msg = MessageThree.decode(test_vectors['I']['message_3'])

    suite(msg, test_vectors)


def suite(msg, test_vectors):
    # assert msg.conn_idr == test_vectors['R']['conn_id']
    assert msg.ciphertext == test_vectors['I']['ciphertext_3']
    assert msg.encode() == test_vectors['I']['message_3']
