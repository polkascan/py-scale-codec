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
from scalecodec.types import Vec, String, U16


class TestVec(unittest.TestCase):

    def test_vec_string_encode_decode(self):

        value = ['test', 'vec']

        obj = Vec(String).new()
        data = obj.encode(value)

        obj = Vec(String).new()

        self.assertEqual(value, obj.decode(data))

    def test_vec_integer(self):

        obj = Vec(U16).new()

        value = [1, 2]
        data = obj.encode(value)

        self.assertEqual(data, ScaleBytes('0x0801000200'))
        self.assertEqual(value, obj.decode(data))

        self.assertEqual(obj.value_object[0].value, 1)
        self.assertEqual(obj.value_object[1].value, 2)


if __name__ == '__main__':
    unittest.main()
