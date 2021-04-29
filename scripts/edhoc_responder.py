#!/usr/bin/env python3

import asyncio
import logging
import sys
from binascii import unhexlify
from typing import Union

import aiocoap
import aiocoap.resource as resource
from cose import headers
from cose.algorithms import Sha256Trunc64
from cose.curves import Ed25519, X25519
from cose.extensions.x509 import X5T
from cose.keys import OKPKey
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.x509 import Certificate

from edhoc.definitions import EdhocState, CipherSuite1, CipherSuite0
from edhoc.exceptions import EdhocException
from edhoc.roles.edhoc import CoseHeaderMap, RPK
from edhoc.roles.responder import Responder

logging.basicConfig(level=logging.INFO)
logging.getLogger("coap-server").setLevel(logging.INFO)

with open("responder-cert.pem", "rb") as f:
    c = b"".join(f.readlines())

responder_cert = x509.load_pem_x509_certificate(c)

cert_hash = X5T.from_certificate(Sha256Trunc64, responder_cert.tbs_certificate_bytes).encode()
cred_id_responder = {headers.X5t: cert_hash}

with open("responder-authkey.pem", "rb") as f:
    k = b"".join(f.readlines())

key = load_pem_private_key(k, password=None)

responder_authkey = OKPKey(crv=Ed25519,
                           d=key.private_bytes(serialization.Encoding.Raw,
                                               serialization.PrivateFormat.Raw,
                                               serialization.NoEncryption()),
                           x=key.public_key().public_bytes(serialization.Encoding.Raw,
                                                           serialization.PublicFormat.Raw))


class EdhocResponder(resource.Resource):

    def __init__(self, cred_idr, cred, auth_key):
        super().__init__()
        # test with static connection identifier and static ephemeral key

        self.ephemeral_key = OKPKey(
            crv=X25519,
            x=unhexlify("71a3d599c21da18902a1aea810b2b6382ccd8d5f9bf0195281754c5ebcaf301e"),
            d=unhexlify("fd8cd877c9ea386e6af34ff7e606c4b64ca831c8ba33134fd4cd7167cabaecda"))

        self.cred_idr = cred_idr
        self.cred = cred
        self.auth_key = auth_key
        self.supported = [CipherSuite0, CipherSuite1]

        self.resp = self.create_responder()

    @classmethod
    def get_peer_cred(cls, cred_id: CoseHeaderMap) -> Union[Certificate, RPK]:
        with open("initiator-cert.pem", "rb") as file:
            cert = b"".join(file.readlines())

        initiator_cert = x509.load_pem_x509_certificate(cert)

        return initiator_cert

    def create_responder(self):
        return Responder(conn_idr=unhexlify(b'2b'),
                         cred_idr=self.cred_idr,
                         auth_key=self.auth_key,
                         cred=self.cred,
                         remote_cred_cb=EdhocResponder.get_peer_cred,
                         supported_ciphers=self.supported,
                         ephemeral_key=self.ephemeral_key)

    async def render_post(self, request):

        if self.resp.edhoc_state == EdhocState.EDHOC_WAIT:

            logging.info("POST (%s)  %s", self.resp.edhoc_state, request.payload)

            msg_2 = self.resp.create_message_two(request.payload)
            # assert msg_2 == unhexlify(_msg_2)

            logging.info("CHANGED (%s)  %s", self.resp.edhoc_state, msg_2)

            return aiocoap.Message(code=aiocoap.Code.CHANGED, payload=msg_2)

        elif self.resp.edhoc_state == EdhocState.MSG_2_SENT:
            logging.info("POST (%s)  %s", self.resp.edhoc_state, request.payload)

            conn_idi, conn_idr, aead, hashf = self.resp.finalize(request.payload)

            logging.info('EDHOC key exchange successfully completed:')
            logging.info(f" - connection IDr: {conn_idr}")
            logging.info(f" - connection IDi: {conn_idi}")
            logging.info(f" - aead algorithm: {aead}")
            logging.info(f" - hash algorithm: {hashf}")

            logging.info(f" - OSCORE secret : {self.resp.exporter('OSCORE Master Secret', 16)}")
            logging.info(f" - OSCORE salt   : {self.resp.exporter('OSCORE Master Salt', 8)}")

            # initialize new Responder object
            self.resp = self.create_responder()

            return aiocoap.Message(code=aiocoap.Code.CHANGED)
        else:
            raise EdhocException(f"Illegal state: {self.resp.edhoc_state}")


def main():
    # Resource tree creation
    logging.info('Booting CoAP server')

    root = resource.Site()

    logging.info("Initializing 'core' resource")
    root.add_resource(['.well-known', 'core'], resource.WKCResource(root.get_resources_as_linkheader))

    logging.info("Initializing 'edhoc' resource")
    root.add_resource(['.well-known', 'edhoc'], EdhocResponder(cred_id_responder, responder_cert, responder_authkey))

    if sys.platform.startswith('linux'):
        asyncio.Task(aiocoap.Context.create_server_context(root))
    else:
        asyncio.Task(aiocoap.Context.create_server_context(root, bind=('localhost', None)))

    asyncio.get_event_loop().run_forever()


if __name__ == '__main__':
    main()
