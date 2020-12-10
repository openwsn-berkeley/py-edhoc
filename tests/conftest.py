import json
import os
import pathlib
from binascii import unhexlify
from typing import List

import cbor2
from cose import CoseAlgorithms, OKP, EC2, CoseEllipticCurves
from pytest import fixture

from edhoc.definitions import CipherSuite, Method
from edhoc.roles.initiator import Initiator
from edhoc.roles.responder import Responder

path_tests = os.path.join(pathlib.Path(__file__).parent.absolute(), 'vectors')
test_vector_path = [os.path.join(path_tests, file) for file in os.listdir(path_tests)]


def pytest_generate_tests(metafunc):
    if "test_vectors" in metafunc.fixturenames:
        test_suite = edhoc_test_vectors()
        ids = ["test_vector_" + str(v["vector"]) for v in test_suite]
        metafunc.parametrize("test_vectors", test_suite, ids=ids)


def edhoc_test_vectors() -> List[dict]:
    return [json.load(open(file, 'r'), object_hook=type_conversion) for file in test_vector_path]


def setup_sign_key(selected_cipher: int, private_bytes: bytes):
    if CipherSuite(selected_cipher).sign_curve in [CoseEllipticCurves.ED448, CoseEllipticCurves.ED25519]:
        return OKP(d=private_bytes,
                   crv=CipherSuite(selected_cipher).sign_curve,
                   alg=CipherSuite(selected_cipher).sign_alg)
    elif CipherSuite(selected_cipher).sign_alg == CoseAlgorithms.ES256:
        return EC2(d=private_bytes, alg=CoseAlgorithms.ES256, crv=CipherSuite(selected_cipher).sign_curve)
    else:
        raise ValueError("Illegal signing keys.")


def setup_dh_key(selected_cipher: int, private_bytes: bytes):
    if CipherSuite(selected_cipher).dh_curve in [CoseEllipticCurves.X448, CoseEllipticCurves.X25519]:
        return OKP(d=private_bytes, crv=CipherSuite(selected_cipher).dh_curve)
    elif CipherSuite(selected_cipher).dh_curve in [CoseEllipticCurves.P_256]:
        return EC2(d=private_bytes, crv=CipherSuite(selected_cipher).sign_curve)
    else:
        raise ValueError("Illegal DH keys.")


def type_conversion(decoded: dict):
    if 'I' not in decoded or 'R' not in decoded:
        return decoded

    for x in ['I', 'R']:
        if x == "I":
            decoded[x]["ad_1"] = unhexlify(decoded[x]["ad_1"])
            decoded[x]["ad_3"] = unhexlify(decoded[x]["ad_1"])
            decoded[x]['x'] = unhexlify(decoded[x]['x'])
            decoded[x]['g_x'] = unhexlify(decoded[x]['g_x'])

            if int(decoded['S']['method']) in [Method.SIGN_SIGN, Method.SIGN_STATIC]:
                decoded[x]['sk'] = setup_sign_key(decoded['I']['selected'], unhexlify(decoded[x]['sk']))
            else:
                decoded[x]['sk'] = setup_dh_key(decoded['I']['selected'], unhexlify(decoded[x]['sk']))

            decoded[x]['message_1'] = unhexlify(decoded[x]['message_1'])
            decoded[x]['prk_4x3m'] = unhexlify(decoded[x]['prk_4x3m'])
            decoded[x]['data_3'] = unhexlify(decoded[x]['data_3'])
            decoded[x]['input_th_3'] = unhexlify(decoded[x]['input_th_3'])
            decoded[x]['th_3'] = unhexlify(decoded[x]['th_3'])
            decoded[x]['p_3m'] = unhexlify(decoded[x]['p_3m'])
            decoded[x]['eaad_3m'] = cbor2.loads(unhexlify(decoded[x]['a_3m']))[2]
            decoded[x]['k_3m'] = unhexlify(decoded[x]['k_3m'])
            decoded[x]['iv_3m'] = unhexlify(decoded[x]['iv_3m'])
            decoded[x]['mac3'] = unhexlify(decoded[x]["mac_3"])
            decoded[x]["sign_or_mac3"] = unhexlify(decoded[x]["sign_or_mac3"])
            decoded[x]["p_3ae"] = unhexlify(decoded[x]["p_3ae"])
            decoded[x]["k_3ae"] = unhexlify(decoded[x]["k_3ae"])
            decoded[x]["iv_3ae"] = unhexlify(decoded[x]["iv_3ae"])
            decoded[x]["ciphertext_3"] = unhexlify(decoded[x]["ciphertext_3"])
            decoded[x]['message_3'] = unhexlify(decoded[x]['message_3'])
        if x == "R":
            decoded[x]["ad_2"] = unhexlify(decoded[x]["ad_2"])
            decoded[x]['y'] = unhexlify(decoded[x]['y'])
            decoded[x]['g_y'] = unhexlify(decoded[x]['g_y'])

            if int(decoded['S']['method']) in [Method.SIGN_SIGN, Method.STATIC_SIGN]:
                decoded[x]['sk'] = setup_sign_key(decoded['I']['selected'], unhexlify(decoded[x]['sk']))
            else:
                decoded[x]['sk'] = setup_dh_key(decoded['I']['selected'], unhexlify(decoded[x]['sk']))

            decoded[x]['prk_2e'] = unhexlify(decoded[x]['prk_2e'])
            decoded[x]['prk_3e2m'] = unhexlify(decoded[x]['prk_3e2m'])
            decoded[x]['data_2'] = unhexlify(decoded[x]['data_2'])
            decoded[x]['input_th_2'] = unhexlify(decoded[x]['input_th_2'])
            decoded[x]['th_2'] = unhexlify(decoded[x]['th_2'])
            decoded[x]['info_k_2m'] = unhexlify(decoded[x]['info_k_2m'])
            decoded[x]['a_2m'] = unhexlify(decoded[x]['a_2m'])
            decoded[x]['eaad_2m'] = cbor2.loads(decoded[x]['a_2m'])[2]
            decoded[x]['k_2m'] = unhexlify(decoded[x]['k_2m'])
            decoded[x]['iv_2m'] = unhexlify(decoded[x]['iv_2m'])
            decoded[x]['mac2'] = unhexlify(decoded[x]["mac_2"])
            decoded[x]["sign_or_mac2"] = unhexlify(decoded[x]["sign_or_mac2"])
            decoded[x]["p_2e"] = unhexlify(decoded[x]["p_2e"])
            decoded[x]["k_2e"] = unhexlify(decoded[x]["k_2e"])
            decoded[x]["ciphertext_2"] = unhexlify(decoded[x]["ciphertext_2"])
            decoded[x]['message_2'] = unhexlify(decoded[x]['message_2'])

        decoded[x]['conn_id'] = unhexlify(decoded[x]['conn_id'])
        decoded[x]['id_cred'] = cbor2.loads(unhexlify(decoded[x]['id_cred']))
        decoded[x]['cred'] = unhexlify(decoded[x]['cred'])
        decoded[x]['subject_name'] = str(decoded[x]['subject_name'])

    decoded['S']['g_xy'] = unhexlify(decoded['S']['g_xy'])

    return decoded


@fixture
def ephemeral_responder_key(test_vectors):
    return OKP(
        x=test_vectors['R']['g_y'],
        d=test_vectors['R']['y'],
        crv=CipherSuite(test_vectors['I']['selected']).dh_curve)


@fixture
def responder(ephemeral_responder_key, test_vectors):
    return Responder(
        conn_idr=test_vectors["R"]["conn_id"],
        cred_idr=test_vectors['R']['id_cred'],
        auth_key=test_vectors['R']['sk'],
        cred=test_vectors["R"]["cred"],
        supported_ciphers=test_vectors["S"]["supported"],
        peer_cred=test_vectors['I']['cred'],
        ephemeral_key=ephemeral_responder_key
    )


@fixture
def ephemeral_initiator_key(test_vectors):
    return OKP(
        x=test_vectors['I']['g_x'],
        d=test_vectors['I']['x'],
        crv=CipherSuite(test_vectors['I']['selected']).dh_curve)


@fixture
def initiator(ephemeral_initiator_key, test_vectors):
    return Initiator(
        corr=test_vectors['S']['corr'],
        method=test_vectors['S']['method'],
        cred=test_vectors['I']['cred'],
        cred_idi=test_vectors['I']['id_cred'],
        auth_key=test_vectors['I']['sk'],
        selected_cipher=test_vectors['I']['selected'],
        supported_ciphers=test_vectors['I']['supported'],
        conn_idi=test_vectors['I']['conn_id'],
        peer_cred=test_vectors['R']['cred'],
        ephemeral_key=ephemeral_initiator_key,
    )
