import json
import os
import pathlib
from binascii import unhexlify
from typing import List

path_tests = os.path.join(pathlib.Path(__file__).parent.absolute(), 'vectors')
test_vectors = [os.path.join(path_tests, file) for file in os.listdir(path_tests)]


def pytest_generate_tests(metafunc):
    if "message1_tests" in metafunc.fixturenames:
        test_suite = edhoc_test_vectors()
        ids = ["message1_test_" + str(i) for i in range(1, len(test_suite) + 1)]
        metafunc.parametrize("message1_tests", test_suite, ids=ids)


def edhoc_test_vectors() -> List[dict]:
    return [json.load(open(file, 'r'), object_hook=type_conversion) for file in test_vectors]


def type_conversion(decoded: dict):
    if 'I' not in decoded or 'R' not in decoded:
        return decoded

    for x in ['I', 'R']:
        decoded[x]['x'] = unhexlify(decoded[x]['x'])
        decoded[x]['g_x'] = unhexlify(decoded[x]['g_x'])
        decoded[x]['conn_id'] = unhexlify(decoded[x]['conn_id'])
        if "ad1" in decoded[x]:
            decoded[x]["ad1"] = unhexlify(decoded[x]["ad1"])
        if "ad2" in decoded[x]:
            decoded[x]["ad2"] = unhexlify(decoded[x]["ad2"])

    return decoded
