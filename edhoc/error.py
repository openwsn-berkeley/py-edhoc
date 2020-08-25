from typing import List, Union, Optional

from edhoc.suites import BaseCipherSuite


class MessageError:
    def __init__(self,
                 err_msg: str,
                 conn_id: bytes = b'',
                 suites_r: Optional[Union[List[BaseCipherSuite], BaseCipherSuite]] = None):
        self.err_msg = err_msg
        self.conn_id = conn_id
        self.suites_r = suites_r
