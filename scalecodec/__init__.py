# Python SCALE Codec Library
#
# Copyright 2018-2024 Stichting Polkascan (Polkascan Foundation).
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

if os.getenv('GITHUB_REF'):
    if not os.getenv('GITHUB_REF').startswith('refs/tags/v'):
        raise ValueError('Incorrect tag format {}'.format(os.getenv('GITHUB_REF')))
    __version__ = os.getenv('GITHUB_REF').replace('refs/tags/v', '')
else:
    __version__ = '2.0.0-dev1'
