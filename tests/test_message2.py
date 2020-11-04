from binascii import unhexlify

from edhoc.messages.message2 import MessageTwo


def test_message2_decode(message1_tests):
    msg = MessageTwo.decode(unhexlify(message1_tests['R']['message_2']))

