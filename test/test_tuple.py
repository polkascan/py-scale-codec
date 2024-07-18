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
from scalecodec.types import Tuple, Compact, U32, U8


class TestTuple(unittest.TestCase):

    def test_tuple_decode(self):
        obj = Tuple(Compact(U32), Compact(U32)).new()
        obj.decode(ScaleBytes("0x0c00"))
        self.assertEqual(obj.value, (3, 0))

    def test_tuple_encode_decode(self):
        scale_obj = Tuple(U8, U8).new()
        value = (1, 5)

        data = scale_obj.encode(value)
        scale_obj.decode(data)

        self.assertEqual(value, scale_obj.value)

    def test_tuple_deserialize(self):
        obj = Tuple(Compact(U32), Compact(U32)).new()
        obj.deserialize((3, 2))
        self.assertEqual(obj.value, (3, 2))

    def test_tuple_single_value(self):
        # PolkadotJS compatilibity
        obj = Tuple(U8).new()
        obj.decode(ScaleBytes('0x03'))
        self.assertEqual(obj.value, 3)
        self.assertEqual(obj.value_object, U8.new(value=3))


if __name__ == '__main__':
    unittest.main()
