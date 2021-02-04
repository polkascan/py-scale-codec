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
import os
import requests

from scalecodec.type_registry import SUPPORTED_TYPE_REGISTRY_PRESETS, ONLINE_BASE_URL


def update_type_registries():

    for type_registry in SUPPORTED_TYPE_REGISTRY_PRESETS:

        result = requests.get(f'{ONLINE_BASE_URL}{type_registry}.json')

        if result.status_code == 200:
            remote_type_reg = result.content

            module_path = os.path.dirname(__file__)
            path = os.path.join(module_path, 'type_registry/{}.json'.format(type_registry))

            f = open(path, 'wb')
            f.write(remote_type_reg)
            f.close()


if __name__ == '__main__':
    print('Updating type registries...')
    update_type_registries()
    print('Type registries updated')
