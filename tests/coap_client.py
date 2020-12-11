import argparse
import asyncio
import logging
import pickle
from binascii import unhexlify

import cbor2
from aiocoap import Context, Message
from aiocoap.numbers.codes import Code
from cose import CoseEllipticCurves, CoseAlgorithms, OKP, CoseHeaderKeys

from edhoc.definitions import CipherSuite, Correlation, Method
from edhoc.roles.edhoc import CoseHeaderMap
from edhoc.roles.initiator import Initiator

logging.basicConfig(level=logging.INFO)

_msg_3 = b'1358582d88ff86da47482c0dfa559ac824a4a783d870c9dba47805e8aafbad6974c49646586503fa9bbf3e00012c037eaf56e45' \
         b'e301920839b813a53f6d4c557480f6c797d5b76f0e462f5f57a3db6d2b50c32319f340f4ac5af9a'

# private signature key
private_key = OKP(
    crv=CoseEllipticCurves.ED25519,
    alg=CoseAlgorithms.EDDSA,
    d=unhexlify("2ffce7a0b2b825d397d0cb54f746e3da3f27596ee06b5371481dc0e012bc34d7")
)

# certificate (should contain the pubkey but is just a random string)
cert = "5865fa34b22a9ca4a1e12924eae1d1766088098449cb848ffc795f88afc49cbe8afdd1ba009f21675e8f6c77a4a2c30195601f6f0a" \
       "0852978bd43d28207d44486502ff7bdda632c788370016b8965bdb2074bff82e5a20e09bec21f8406e86442b87ec3ff245b7"

cert = unhexlify(cert)

cred_id = cbor2.loads(unhexlify(b"a11822822e485b786988439ebcf2"))

with open("cred_store.pickle", 'rb') as h:
    credentials_storage = pickle.load(h)


async def main():
    parser = argparse.ArgumentParser()

    # 51.75.194.248
    parser.add_argument("ip", help="IP address of EDHOC responder", type=str)
    parser.add_argument("--epk", help="Use a preset ephemeral key", action="store_true")

    args = parser.parse_args()

    context = await Context.create_client_context()

    supported = [CipherSuite.SUITE_0]

    if args.epk:
        ephemeral_key = OKP(
            crv=CoseEllipticCurves.X25519,
            x=unhexlify("898ff79a02067a16ea1eccb90fa52246f5aa4dd6ec076bba0259d904b7ec8b0c"),
            d=unhexlify("8f781a095372f85b6d9f6109ae422611734d7dbfa0069a2df2935bb2e053bf35"))
    else:
        ephemeral_key = None

    init = Initiator(
        corr=Correlation.CORR_1,
        method=Method.SIGN_SIGN,
        conn_idi=unhexlify(b''),
        cred_idi=cred_id,
        auth_key=private_key,
        cred=cert,
        peer_cred=get_peer_cred,
        supported_ciphers=supported,
        selected_cipher=CipherSuite.SUITE_0,
        ephemeral_key=ephemeral_key)

    msg_1 = init.create_message_one()
    # assert msg_1 == unhexlify(b"01005820898ff79a02067a16ea1eccb90fa52246f5aa4dd6ec076bba0259d904b7ec8b0c40")

    request = Message(code=Code.POST, payload=msg_1, uri=f"coap://{args.ip}/.well-known/edhoc")

    logging.info("POST (%s)  %s", init.edhoc_state, request.payload)
    response = await context.request(request).response

    logging.info("CHANGED (%s)  %s", init.edhoc_state, response.payload)
    msg_3 = init.create_message_three(response.payload)
    # assert msg_3 == unhexlify(_msg_3)

    logging.info("POST (%s)  %s", init.edhoc_state, request.payload)
    request = Message(code=Code.POST, payload=msg_3, uri="coap://51.75.194.248/.well-known/edhoc")
    response = await context.request(request).response

    logging.info('EDHOC key exchange successfully completed')


def get_peer_cred(cred_id: CoseHeaderMap):
    identifier = int.from_bytes(cred_id[CoseHeaderKeys.X5_T][1], byteorder="big")
    try:
        return unhexlify(credentials_storage[identifier])
    except KeyError:
        return None


if __name__ == "__main__":
    asyncio.get_event_loop().run_until_complete(main())
