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
from scalecodec.types import U16, I16, U8


class TestInteger(unittest.TestCase):

    def test_u16_decode(self):
        obj = U16.new()
        obj.decode(ScaleBytes("0x2efb"))
        self.assertEqual(obj.value, 64302)

    def test_i16_decode(self):
        obj = I16.new()
        obj.decode(ScaleBytes("0x2efb"))
        self.assertEqual(obj.value, -1234)

    def test_u16(self):
        obj = U16.new()
        obj.encode(64302)
        self.assertEqual(str(obj.data), "0x2efb")

    def test_i16_encode(self):
        obj = I16.new()
        obj.encode(-1234)
        self.assertEqual(str(obj.data), "0x2efb")

    def test_i16_encode_out_of_bounds(self):
        obj = I16.new()
        self.assertRaises(OverflowError, obj.encode, -32769)

    def test_u8(self):
        scale_obj = U8.new()
        value = 42

        data = scale_obj.encode(value)
        scale_obj.decode(data)

        self.assertEqual(value, scale_obj.value)

if __name__ == '__main__':
    unittest.main()
