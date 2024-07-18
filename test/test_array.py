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
from scalecodec.exceptions import ScaleEncodeException
from scalecodec.types import Array, U32, U8


class TestArray(unittest.TestCase):

    def test_dynamic_fixed_array_type_decode(self):
        obj = Array(U32, 1).new()
        self.assertEqual([1], obj.decode(ScaleBytes("0x01000000")))

        obj = Array(U32, 3).new()
        self.assertEqual([1, 2, 3], obj.decode(ScaleBytes("0x010000000200000003000000")))

        obj = Array(U32, 0).new()
        self.assertEqual([], obj.decode(ScaleBytes(bytes())))

    def test_dynamic_fixed_array_type_decode_u8(self):
        obj = Array(U8, 65).new()
        obj.decode(ScaleBytes(
                "0xc42b82d02bce3202f6a05d4b06d1ad46963d3be36fd0528bbe90e7f7a4e5fcd38d14234b1c9fcee920d76cfcf43b4ed5dd718e357c2bc1aae3a642975207e67f01"
        ))
        self.assertEqual(
            "0xc42b82d02bce3202f6a05d4b06d1ad46963d3be36fd0528bbe90e7f7a4e5fcd38d14234b1c9fcee920d76cfcf43b4ed5dd718e357c2bc1aae3a642975207e67f01",
            obj.value
        )

    def test_array_type_encode_u8(self):
        obj = Array(U8, 2).new()
        self.assertEqual('0x0102', str(obj.encode('0x0102')))
        self.assertEqual('0x0102', str(obj.encode(b'\x01\x02')))
        self.assertEqual('0x0102', str(obj.encode([1, 2])))

    def test_array_type_encode(self):
        obj = Array(U32, 2).new()
        self.assertEqual('0x0100000002000000', str(obj.encode([1, 2])))

        obj = Array(U8, 3).new()
        self.assertEqual('0x010203', str(obj.encode('0x010203')))

    def test_invalid_array_encode(self):
        obj = Array(U8, 3).new()
        self.assertRaises(ScaleEncodeException, obj.encode, '0x0102')

        obj = Array(U32, 3).new()
        self.assertRaises(ScaleEncodeException, obj.encode, '0x0102')

    def test_array_u8(self):
        obj = Array(U8, 4).new()

        value = [1, 2, 3, 4]
        data = obj.encode(value)

        self.assertEqual(data, ScaleBytes('0x01020304'))

        data.reset()
        self.assertEqual('0x01020304', obj.decode(data))

        self.assertEqual(obj.value_object, b'\x01\x02\x03\x04')


if __name__ == '__main__':
    unittest.main()
