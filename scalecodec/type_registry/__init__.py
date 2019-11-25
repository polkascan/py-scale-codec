import os
import json


def load_type_registry_preset(name):
    module_path = os.path.dirname(__file__)
    path = os.path.join(module_path, '{}.json'.format(name))
    return load_type_registry_file(path)


def load_type_registry_file(file_path):

    with open(os.path.abspath(file_path), 'r') as fp:
        data = fp.read()

    return json.loads(data)
