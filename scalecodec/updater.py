# Python SCALE Codec Library
#
# Copyright 2018-2020 Stichting Polkascan (Polkascan Foundation).
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
import json
import os

import requests

TYPE_REGISTRY_CONFIG = [
    {
        'name': 'default',
        'remote': 'https://raw.githubusercontent.com/polkascan/py-scale-codec/master/scalecodec/type_registry/default.json'
    },
    {
        'name': 'polkadot',
        'remote': 'https://raw.githubusercontent.com/polkascan/py-scale-codec/master/scalecodec/type_registry/polkadot.json'
    },
    {
        'name': 'kusama',
        'remote': 'https://raw.githubusercontent.com/polkascan/py-scale-codec/master/scalecodec/type_registry/kusama.json'
    },
    {
        'name': 'westend',
        'remote': 'https://raw.githubusercontent.com/polkascan/py-scale-codec/master/scalecodec/type_registry/westend.json'
    },
    {
        'name': 'rococo',
        'remote': 'https://raw.githubusercontent.com/polkascan/py-scale-codec/master/scalecodec/type_registry/rococo.json'
    },
    {
        'name': 'canvas',
        'remote': 'https://raw.githubusercontent.com/polkascan/py-scale-codec/master/scalecodec/type_registry/canvas.json'
    },
    {
        'name': 'development',
        'remote': 'https://raw.githubusercontent.com/polkascan/py-scale-codec/master/scalecodec/type_registry/development.json'
    },
    {
        'name': 'substrate-node-template',
        'remote': 'https://raw.githubusercontent.com/polkascan/py-scale-codec/master/scalecodec/type_registry/substrate-node-template.json'
    }
]


def update_type_registries():

    for type_registry in TYPE_REGISTRY_CONFIG:

        remote_type_reg = requests.get(type_registry['remote']).content

        module_path = os.path.dirname(__file__)
        path = os.path.join(module_path, 'type_registry/{}.json'.format(type_registry['name']))

        f = open(path, 'wb')
        f.write(remote_type_reg)
        f.close()


if __name__ == '__main__':
    print('Updating type registries...')
    update_type_registries()
    print('Type registries updated')
