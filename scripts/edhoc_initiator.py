#!/usr/bin/env python3

import argparse
import asyncio
import logging
import sys
from binascii import unhexlify

from aiocoap import Context, Message
from aiocoap.numbers.codes import Code
from cose import headers
from cose.algorithms import Sha256Trunc64
from cose.keys.curves import X25519, Ed25519
from cose.extensions.x509 import X5T
from cose.keys import OKPKey
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import load_pem_private_key

from edhoc.definitions import Correlation, Method, CipherSuite0
from edhoc.roles.edhoc import CoseHeaderMap
from edhoc.roles.initiator import Initiator

logging.basicConfig(level=logging.INFO)

with open("initiator-cert.pem", "rb") as f:
    c = b"".join(f.readlines())

initiator_cert = x509.load_pem_x509_certificate(c)

cert_hash = X5T.from_certificate(Sha256Trunc64, initiator_cert.tbs_certificate_bytes).encode()
cred_id_initiator = {headers.X5t: cert_hash}

with open("initiator-authkey.pem", "rb") as f:
    k = b"".join(f.readlines())

key = load_pem_private_key(k, password=None)

initiator_authkey = OKPKey(crv=Ed25519,
                           d=key.private_bytes(serialization.Encoding.Raw,
                                               serialization.PrivateFormat.Raw,
                                               serialization.NoEncryption()),
                           x=key.public_key().public_bytes(serialization.Encoding.Raw,
                                                           serialization.PublicFormat.Raw))


async def main():
    parser = argparse.ArgumentParser()

    # 51.75.194.248
    parser.add_argument("ip", help="IP address of EDHOC responder", type=str)
    parser.add_argument("--epk", help="Use a preset ephemeral key", action="store_true")

    args = parser.parse_args()

    context = await Context.create_client_context()

    supported = [CipherSuite0]

    if args.epk:
        ephemeral_key = OKPKey(
            crv=X25519,
            x=unhexlify("898ff79a02067a16ea1eccb90fa52246f5aa4dd6ec076bba0259d904b7ec8b0c"),
            d=unhexlify("8f781a095372f85b6d9f6109ae422611734d7dbfa0069a2df2935bb2e053bf35"))
    else:
        ephemeral_key = None

    init = Initiator(
        corr=Correlation.CORR_1,
        method=Method.SIGN_SIGN,
        conn_idi=unhexlify(b''),
        cred_idi=cred_id_initiator,
        auth_key=initiator_authkey,
        cred=initiator_cert,
        remote_cred_cb=get_peer_cred,
        supported_ciphers=supported,
        selected_cipher=CipherSuite0,
        ephemeral_key=ephemeral_key)

    msg_1 = init.create_message_one()
    # assert msg_1 == unhexlify(b"01005820898ff79a02067a16ea1eccb90fa52246f5aa4dd6ec076bba0259d904b7ec8b0c40")

    request = Message(code=Code.POST, payload=msg_1, uri=f"coap://[{args.ip}]/.well-known/edhoc")

    logging.info("POST (%s)  %s", init.edhoc_state, request.payload)
    response = await context.request(request).response

    logging.info("CHANGED (%s)  %s", init.edhoc_state, response.payload)
    msg_3 = init.create_message_three(response.payload)
    # assert msg_3 == unhexlify(_msg_3)

    logging.info("POST (%s)  %s", init.edhoc_state, request.payload)
    request = Message(code=Code.POST, payload=msg_3, uri=f"coap://[{args.ip}]/.well-known/edhoc")
    response = await context.request(request).response

    conn_idi, conn_idr, aead, hashf = init.finalize()

    logging.info('EDHOC key exchange successfully completed:')
    logging.info(f" - connection IDr: {conn_idr}")
    logging.info(f" - connection IDi: {conn_idi}")
    logging.info(f" - aead algorithm: {aead}")
    logging.info(f" - hash algorithm: {hashf}")

    logging.info(f" - OSCORE secret : {init.exporter('OSCORE Master Secret', 16)}")
    logging.info(f" - OSCORE salt   : {init.exporter('OSCORE Master Salt', 8)}")


def get_peer_cred(cred_id: CoseHeaderMap):
    with open("responder-cert.pem", "rb") as file:
        cert = b"".join(file.readlines())

    responder_cert = x509.load_pem_x509_certificate(cert)

    return responder_cert


def sync_main():
    try:
        asyncio.get_event_loop().run_until_complete(main())
    except KeyboardInterrupt:
        sys.exit(3)


if __name__ == "__main__":
    sync_main()
