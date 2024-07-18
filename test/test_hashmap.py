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
#

import unittest

from scalecodec.base import ScaleBytes
from scalecodec.types import String, HashMap, U32


class TestHashmap(unittest.TestCase):

    def test_hashmap_encode(self):
        obj = HashMap(String, U32).new()
        data = obj.encode([('1', 2), ('23', 24), ('28', 30), ('45', 80)])
        self.assertEqual(data.to_hex(), '0x10043102000000083233180000000832381e00000008343550000000')

    def test_hashmap_decode(self):
        obj = HashMap(String, U32).new()
        data = ScaleBytes("0x10043102000000083233180000000832381e00000008343550000000")
        self.assertEqual([('1', 2), ('23', 24), ('28', 30), ('45', 80)], obj.decode(data))


if __name__ == '__main__':
    unittest.main()
