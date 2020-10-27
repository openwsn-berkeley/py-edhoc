class EdhocCipherException(Exception):
    """ Exception related to the configuration of the selected and supported ciphers. """
    pass


class EdhocInvalidMessage(Exception):
    """ Invalid EDHOC message. """
    pass
