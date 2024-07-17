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
import unittest

from scalecodec.base import ScaleBytes

from scalecodec.types import Compact, U16, I16, U32, Vec, Bytes, String, Option, F64, F32, U128


class TestScaleTypeEncoding(unittest.TestCase):

    def test_u16(self):
        obj = U16.new()
        obj.encode(64302)
        self.assertEqual(str(obj.data), "0x2efb")

    def test_i16(self):
        obj = I16.new()
        obj.encode(-1234)
        self.assertEqual(str(obj.data), "0x2efb")

    def test_i16_out_of_bounds(self):
        obj = I16.new()
        self.assertRaises(OverflowError, obj.encode, -32769)

    def test_f64(self):
        obj = F64.new()
        obj.encode(-0.0)
        self.assertEqual(str(obj.data), "0x0000000000000080")

    def test_f64_invalid_input(self):
        obj = F64.new()
        with self.assertRaises(ValueError) as cm:
            obj.encode(-0)
            self.assertEqual('0 is not a float', str(cm.exception))

    def test_f32(self):
        obj = F32.new()
        obj.encode(-0.0)
        self.assertEqual(str(obj.data), "0x00000080")

    def test_compact_u32_1byte(self):
        obj = Compact(U32).new()
        obj.decode(ScaleBytes("0x18"))

        obj = Compact(U32).new()
        obj.encode(6)
        self.assertEqual(str(obj.data), "0x18")

    def test_compact_u32_2bytes(self):
        obj = Compact(U32).new()
        obj.encode(6000)
        self.assertEqual(str(obj.data), "0xc15d")

    def test_compact_u32_4bytes(self):

        obj = Compact(U32).new()
        obj.encode(1000000)
        self.assertEqual(str(obj.data), "0x02093d00")

    def test_compact_u32_larger_than_4bytes(self):

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

    def test_vec_string_encode_decode(self):

        value = ['test', 'vec']

        obj = Vec(String).new()
        data = obj.encode(value)

        obj = Vec(String).new()

        self.assertEqual(value, obj.decode(data))


    def test_bytes_encode_decode(self):

        value = 'This is a test'

        obj = String.new()
        data = obj.encode(value)

        obj_check = String.new()

        self.assertEqual(obj_check.decode(data), value)

    def test_bytes_encode_bytes(self):
        value = b'This is a test'

        obj = Bytes.new()
        data = obj.encode(value)

        self.assertEqual("0x385468697320697320612074657374", data.to_hex())

    def test_bytes_encode_bytearray(self):
        value = bytearray(b'This is a test')

        obj = Bytes.new()
        data = obj.encode(value)

        self.assertEqual("0x385468697320697320612074657374", data.to_hex())

    def test_bytes_encode_list_of_u8(self):
        value = [84, 104, 105, 115, 32, 105, 115, 32, 97, 32, 116, 101, 115, 116]

        obj = Bytes.new()
        data = obj.encode(value)

        self.assertEqual("0x385468697320697320612074657374", data.to_hex())

    def test_hexbytes_encode_decode(self):

        value = '0x5468697320697320612074657374'

        obj = Bytes.new()
        data = obj.encode(value)

        obj_check = Bytes.new()

        self.assertEqual(obj_check.decode(data), value)

    def test_compact_balance_encode_decode(self):
        scale_data = ScaleBytes('0x070010a5d4e8')
        value = 1000000000000

        Balance = U128

        obj = Compact(Balance).new()
        data = obj.encode(value)

        self.assertEqual(str(scale_data), str(data))

        self.assertEqual(obj.decode(data), value)

    def test_option_empty_encode_decode(self):

        value = None

        obj = Option(Bytes).new()
        data = obj.encode(value)

        self.assertEqual(obj.decode(data), value)

    def test_option_string_encode_decode(self):
        value = "Test"

        obj = Option(String).new()
        data = obj.encode(value)

        self.assertEqual(obj.decode(data), value)
