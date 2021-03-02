import asyncio
import logging
import pickle
from binascii import unhexlify
from pathlib import Path

import aiocoap
import aiocoap.resource as resource
import cbor2
from cose import OKP, CoseEllipticCurves, CoseAlgorithms, CoseHeaderKeys

from edhoc.definitions import CipherSuite, EdhocState
from edhoc.exceptions import EdhocException
from edhoc.roles.edhoc import CoseHeaderMap
from edhoc.roles.responder import Responder

logging.basicConfig(level=logging.INFO)
logging.getLogger("coap-server").setLevel(logging.INFO)

_msg_2 = b"582071a3d599c21da18902a1aea810b2b6382ccd8d5f9bf0195281754c5ebcaf301e13585099d53801a725bfd6a4e71d0484b755e" \
         b"c383df77a916ec0dbc02bba7c21a200807b4f585f728b671ad678a43aacd33b78ebd566cd004fc6f1d406f01d9704e705b21552a9" \
         b"eb28ea316ab65037d717862e"

# private signature key
private_key = OKP(
    crv=CoseEllipticCurves.ED25519,
    alg=CoseAlgorithms.EDDSA,
    d=unhexlify("df69274d713296e246306365372b4683ced5381bfcadcd440a24c391d2fedb94"))

# certificate (should contain the pubkey but is just a random string)
cert = "586e47624dc9cdc6824b2a4c52e95ec9d6b0534b71c2b49e4bf9031500cee6869979c297bb5a8b381e98db714108415e5c50db78974c" \
       "271579b01633a3ef6271be5c225eb28f9cf6180b5a6af31e80209a085cfbf95f3fdcf9b18b693d6c0e0d0ffb8e3f9a32a50859ecd0bf" \
       "cff2c218"
cert = unhexlify(cert)

cred_id = cbor2.loads(unhexlify(b"a11822822e48fc79990f2431a3f5"))


class EdhocResponder(resource.Resource):
    cred_store = Path(__file__).parent / "cred_store.pickle"

    def __init__(self, cred_idr, cred, auth_key):
        super().__init__()
        # test with static connection identifier and static ephemeral key

        self.ephemeral_key = OKP(
            crv=CoseEllipticCurves.X25519,
            x=unhexlify("71a3d599c21da18902a1aea810b2b6382ccd8d5f9bf0195281754c5ebcaf301e"),
            d=unhexlify("fd8cd877c9ea386e6af34ff7e606c4b64ca831c8ba33134fd4cd7167cabaecda"))

        self.cred_idr = cred_idr
        self.cred = cred
        self.auth_key = auth_key
        self.supported = [CipherSuite.SUITE_0, CipherSuite.SUITE_1, CipherSuite.SUITE_2, CipherSuite.SUITE_3]

        self.resp = self.create_responder()

        with open(self.cred_store, 'rb') as h:
            self.credentials_storage = pickle.load(h)

    def get_peer_cred(self, cred_id: CoseHeaderMap):
        identifier = int.from_bytes(cred_id[CoseHeaderKeys.X5_T][1], byteorder="big")
        try:
            return unhexlify(self.credentials_storage[identifier])
        except KeyError:
            return None

    def create_responder(self):
        return Responder(conn_idr=unhexlify(b'2b'),
                         cred_idr=self.cred_idr,
                         auth_key=self.auth_key,
                         cred=self.cred,
                         peer_cred=self.get_peer_cred,
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
            logging.info(f" - aead algorithm: {CoseAlgorithms(aead)}")
            logging.info(f" - hash algorithm: {CoseAlgorithms(hashf)}")

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
    root.add_resource(['.well-known', 'edhoc'], EdhocResponder(cred_id, cert, private_key))

    asyncio.Task(aiocoap.Context.create_server_context(root))
    asyncio.get_event_loop().run_forever()


if __name__ == '__main__':
    main()
