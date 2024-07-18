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
from scalecodec.types import BitVec


class TestBitvec(unittest.TestCase):

    def test_bitvec_decode(self):
        obj = BitVec().new()
        obj.decode(ScaleBytes('0x0c07'))
        self.assertEqual(obj.value, '0b111')

    def test_bitvec_decode_size2(self):
        obj = BitVec().new()
        obj.decode(ScaleBytes('0x0803'))
        self.assertEqual(obj.value, '0b11')

    def test_bitvec_decode_size_2bytes(self):
        obj = BitVec().new()
        obj.decode(ScaleBytes('0x28fd02'))
        self.assertEqual(obj.value, '0b1011111101')

    def test_bitvec_encode_list(self):
        obj = BitVec().new()
        data = obj.encode([True, True, True])
        self.assertEqual(data.to_hex(), '0x0c07')

    def test_bitvec_encode_list2(self):
        obj = BitVec().new()
        data = obj.encode([True, False])
        self.assertEqual(data.to_hex(), '0x0802')

    def test_bitvec_encode_list3(self):
        obj = BitVec().new()
        data = obj.encode([False, True])
        self.assertEqual(data.to_hex(), '0x0401')

    def test_bitvec_encode_list4(self):
        obj = BitVec().new()
        data = obj.encode([True, False, False, True, True, True, True, True, False, True])
        self.assertEqual(data.to_hex(), '0x287d02')

    def test_bitvec_encode_bin_str(self):
        obj = BitVec().new()
        data = obj.encode('0b00000111')
        self.assertEqual(data.to_hex(), '0x0c07')

    def test_bitvec_encode_bin_str2(self):
        obj = BitVec().new()
        data = obj.encode('0b00000010')
        self.assertEqual(data.to_hex(), '0x0802')

    def test_bitvec_encode_bin_str3(self):
        obj = BitVec().new()
        data = obj.encode('0b00000001')
        self.assertEqual(data.to_hex(), '0x0401')

    def test_bitvec_encode_bin_str4(self):
        obj = BitVec().new()
        data = obj.encode('0b00000010_01111101')
        self.assertEqual(data.to_hex(), '0x287d02')

    def test_bitvec_encode_int(self):
        obj = BitVec().new()
        data = obj.encode(0b00000111)
        self.assertEqual(data.to_hex(), '0x0c07')

    def test_bitvec_encode_int2(self):
        obj = BitVec().new()
        data = obj.encode(0b00000010)
        self.assertEqual(data.to_hex(), '0x0802')

    def test_bitvec_encode_int3(self):
        obj = BitVec().new()
        data = obj.encode(0b00000001)
        self.assertEqual(data.to_hex(), '0x0401')

    def test_bitvec_encode_int4(self):
        obj = BitVec().new()
        data = obj.encode(0b00000010_01111101)
        self.assertEqual(data.to_hex(), '0x287d02')

    def test_bitvec_encode_empty_list(self):
        obj = BitVec().new()
        data = obj.encode([])
        self.assertEqual(data.to_hex(), '0x00')


if __name__ == '__main__':
    unittest.main()
