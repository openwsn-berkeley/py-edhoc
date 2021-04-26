import json
import os
import pathlib
from binascii import unhexlify
from typing import List

import cbor2
from cose.algorithms import Es256
from cose.curves import Ed448, Ed25519, X25519, X448, P256
from cose.keys import EC2Key, OKPKey, CoseKey
from cose.keys.keyparam import KpAlg
from pytest import fixture

from edhoc.definitions import CipherSuite
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
    if CipherSuite.from_id(selected_cipher).sign_curve in [Ed448, Ed25519]:
        return OKPKey(d=private_bytes,
                      crv=CipherSuite.from_id(selected_cipher).sign_curve,
                      optional_params={KpAlg: CipherSuite.from_id(selected_cipher).sign_alg})
    elif CipherSuite.from_id(selected_cipher).sign_alg == Es256:
        return EC2Key(d=private_bytes, alg=Es256, crv=CipherSuite.from_id(selected_cipher).sign_curve)
    else:
        raise ValueError("Illegal COSE curve.")


def setup_dh_key(selected_cipher: int, private_bytes: bytes):
    if CipherSuite.from_id(selected_cipher).dh_curve in [X448, X25519]:
        return OKPKey(d=private_bytes, crv=CipherSuite.from_id(selected_cipher).dh_curve)
    elif CipherSuite.from_id(selected_cipher).dh_curve in [P256]:
        return EC2Key(d=private_bytes, crv=CipherSuite.from_id(selected_cipher).sign_curve)
    else:
        raise ValueError("Illegal DH keys.")


def type_conversion(decoded: dict):
    new_dict = {}

    if 'I' not in decoded or 'R' not in decoded or 'S' not in decoded:
        return decoded

    new_dict.update({'vector': decoded['vector']})

    new_dict.update(
        {'I': {k: (unhexlify(decoded['I'][k]) if isinstance(decoded['I'][k], str) else decoded['I'][k]) for k in
               decoded['I'].keys()}})
    new_dict.update(
        {'R': {k: (unhexlify(decoded['R'][k]) if isinstance(decoded['R'][k], str) else decoded['R'][k]) for k in
               decoded['R'].keys()}})
    new_dict.update(
        {'S': {k: (unhexlify(decoded['S'][k]) if isinstance(decoded['S'][k], str) else decoded['S'][k]) for k in
               decoded['S'].keys()}})
    return new_dict


@fixture
def ephemeral_responder_key(test_vectors):
    return OKPKey(
        x=test_vectors['R']['g_y'],
        d=test_vectors['R']['y'],
        crv=CipherSuite.from_id(test_vectors['I']['selected']).dh_curve)


@fixture
def responder(ephemeral_responder_key, test_vectors):
    if test_vectors['R']['cred_type'] == 0:
        local_cred = cbor2.loads(test_vectors['R']['cred'])
        local_auth_key = None
    else:
        local_cred = CoseKey.decode(test_vectors['R']['cred'])
        local_auth_key = CoseKey.decode(test_vectors['R']['cred'])

    if test_vectors['I']['cred_type'] == 0:
        remote_cred = cbor2.loads(test_vectors['I']['cred'])
        remote_auth_key = None
    else:
        remote_cred = CoseKey.decode(test_vectors['I']['cred'])
        remote_auth_key = CoseKey.decode(test_vectors['I']['cred'])

    responder = Responder(
        conn_idr=test_vectors["R"]["conn_id"],
        cred_idr=cbor2.loads(test_vectors['R']['cred_id']),
        auth_key=CoseKey.decode(test_vectors['R']['auth_key']),
        cred=(local_cred, local_auth_key),
        supported_ciphers=[CipherSuite.from_id(c) for c in test_vectors["R"]["supported"]],
        remote_cred_cb=lambda arg: (remote_cred, remote_auth_key),
        ephemeral_key=ephemeral_responder_key
    )
    responder.cred_idi = test_vectors['I']['cred_id']
    return responder


@fixture
def ephemeral_initiator_key(test_vectors):
    return OKPKey(
        x=test_vectors['I']['g_x'],
        d=test_vectors['I']['x'],
        crv=CipherSuite.from_id(test_vectors['I']['selected']).dh_curve)


@fixture
def initiator(ephemeral_initiator_key, test_vectors):
    if test_vectors['I']['cred_type'] == 0:
        local_auth_key = None
        local_cred = cbor2.loads(test_vectors['I']['cred'])
    else:
        local_auth_key = CoseKey.decode(test_vectors['I']['cred'])
        local_cred = CoseKey.decode(test_vectors['I']['cred'])

    if test_vectors['R']['cred_type'] == 0:
        remote_auth_key = None
        remote_cred = cbor2.loads(test_vectors['R']['cred'])
    else:
        remote_auth_key = CoseKey.decode(test_vectors['R']['cred'])
        remote_cred = CoseKey.decode(test_vectors['R']['cred'])

    initiator = Initiator(
        corr=test_vectors['S']['corr'],
        method=test_vectors['S']['method'],
        cred=(local_cred, local_auth_key),
        cred_idi=cbor2.loads(test_vectors['I']['cred_id']),
        auth_key=CoseKey.decode(test_vectors['I']['auth_key']),
        selected_cipher=test_vectors['I']['selected'],
        supported_ciphers=[CipherSuite.from_id(c) for c in test_vectors["I"]["supported"]],
        conn_idi=test_vectors['I']['conn_id'],
        remote_cred_cb=lambda x: (remote_cred, remote_auth_key),
        ephemeral_key=ephemeral_initiator_key,
    )
    initiator.cred_idr = test_vectors['R']['cred_id']
    return initiator
