class EdhocException(Exception):
    """ Exception related to the configuration of the selected and supported ciphers. """
    pass

class EdhocInvalidMessage(EdhocException):
    """Decoding was attempted assuming a particular message shape that was not provided"""
