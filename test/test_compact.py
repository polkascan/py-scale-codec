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
from scalecodec.exceptions import ScaleDecodeException, RemainingScaleBytesNotEmptyException
from scalecodec.types import Compact, U32, U128


class TestCompact(unittest.TestCase):

    def test_compact_u32(self):
        obj = Compact(U32).new()
        obj.decode(ScaleBytes("0x02093d00"))
        self.assertEqual(obj.value, 1000000)

    def test_compact_u32_1byte(self):
        obj = Compact(U32).new()
        obj.decode(ScaleBytes("0x18"))
        self.assertEqual(obj.value, 6)

    def test_compact_u32_remaining_bytes(self):
        obj = Compact(U32).new()
        with self.assertRaises(ScaleDecodeException):
            obj.decode(ScaleBytes("0x02093d0001"), check_remaining=True)

    def test_compact_u32_invalid(self):
        obj = Compact(U32).new()
        self.assertRaises(RemainingScaleBytesNotEmptyException, obj.decode, ScaleBytes("0x"))

    def test_compact_u32_1byte_encode(self):
        obj = Compact(U32).new()
        obj.decode(ScaleBytes("0x18"))

        obj = Compact(U32).new()
        obj.encode(6)
        self.assertEqual(str(obj.data), "0x18")

    def test_compact_u32_2bytes_encode(self):
        obj = Compact(U32).new()
        obj.encode(6000)
        self.assertEqual(str(obj.data), "0xc15d")

    def test_compact_u32_4bytes_encode(self):

        obj = Compact(U32).new()
        obj.encode(1000000)
        self.assertEqual(str(obj.data), "0x02093d00")

    def test_compact_u32_larger_than_4bytes_encode(self):

        obj = Compact(U32).new()
        obj.encode(150000000000000)
        self.assertEqual(str(obj.data), "0x0b0060b7986c88")

    def test_compact_u32_encode_decode(self):

        value = 2000001

        obj = Compact(U32).new()
        data = obj.encode(value)

        obj = Compact(U32).new()

        self.assertEqual(obj.decode(data), value)

    def test_compact_u32_encode_decode_large(self):

        value = 2**30

        obj = Compact(U32).new()
        data = obj.encode(value)

        obj = Compact(U32).new()

        self.assertEqual(obj.decode(data), value)

    def test_compact_balance_encode_decode(self):
        scale_data = ScaleBytes('0x070010a5d4e8')
        value = 1000000000000

        Balance = U128

        obj = Compact(Balance).new()
        data = obj.encode(value)

        self.assertEqual(str(scale_data), str(data))

        self.assertEqual(obj.decode(data), value)

    def test_balance(self):
        Balance = U128
        obj = Compact(Balance).new()
        obj.decode(ScaleBytes("0x130080cd103d71bc22"))
        self.assertEqual(obj.value, 2503000000000000000)

    def test_compact_no_type(self):
        data = ScaleBytes("0x02093d00")
        compact = Compact().new()
        compact.decode(data)
        self.assertEqual(compact.value, 1000000)

        compact.encode(1000000)
        self.assertEqual(compact.data, data)


if __name__ == '__main__':
    unittest.main()
