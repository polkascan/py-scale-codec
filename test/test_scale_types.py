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

import unittest

from scalecodec.base import ScaleBytes
from scalecodec.exceptions import RemainingScaleBytesNotEmptyException, ScaleEncodeException, ScaleDecodeException

from scalecodec.types import (Compact, U32, U16, I16, Tuple, String, Vec, BitVec, Bool, Array, HashMap, U8,
                              F32, F64, UnsignedInteger)
from scalecodec.utils.ss58 import ss58_encode_account_index


class TestScaleTypes(unittest.TestCase):

    metadata_fixture_dict = {}
    metadata_decoder = None
    runtime_config_v14 = None
    metadata_v14_obj = None

    def test_multiple_decode_without_error(self):
        obj = U16.new()
        obj.decode(ScaleBytes("0x2efb"))
        obj.decode(ScaleBytes("0x2efb"))
        self.assertEqual(obj.value, 64302)

    def test_value_equals_value_serialized_and_value_object(self):
        obj = Tuple(Compact(U32), Compact(U32)).new()
        obj.decode(ScaleBytes("0x0c00"))
        self.assertEqual(obj.value, obj.value_serialized)
        self.assertEqual(obj.value, obj.value_object)

    def test_value_object(self):
        obj = Tuple(Compact(U32), Compact(U32)).new()
        obj.decode(ScaleBytes("0x0c00"))
        self.assertEqual(obj.value_object[0].value_object, 3)
        self.assertEqual(obj.value_object[1].value_object, 0)

    def test_value_object_shorthand(self):
        obj = Tuple(Compact(U32), Compact(U32)).new()
        obj.decode(ScaleBytes("0x0c00"))
        self.assertEqual(obj[0], 3)
        self.assertEqual(obj[1], 0)

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

    def test_u16(self):
        obj = U16.new()
        obj.decode(ScaleBytes("0x2efb"))
        self.assertEqual(obj.value, 64302)

    def test_i16(self):
        obj = I16.new()
        obj.decode(ScaleBytes("0x2efb"))
        self.assertEqual(obj.value, -1234)

    def test_f64(self):
        obj = F64.new()
        obj.decode(ScaleBytes("0x333333333333f33f"))
        self.assertAlmostEqual(obj.value, 1.2)

    def test_f32(self):
        obj = F32.new()
        obj.decode(ScaleBytes("0x9a99993f"))
        self.assertAlmostEqual(obj.value, 1.2)

    def test_bool_true(self):
        obj = Bool().new()
        obj.decode(ScaleBytes("0x01"))
        self.assertEqual(obj.value, True)

    def test_bool_false(self):
        obj = Bool().new()
        obj.decode(ScaleBytes("0x00"))
        self.assertEqual(obj.value, False)

    def test_bool_invalid(self):
        obj = Bool().new()
        self.assertRaises(ScaleDecodeException, obj.decode, ScaleBytes("0x02"))

    def test_string(self):
        obj = String.new()
        obj.decode(ScaleBytes("0x1054657374"))
        self.assertEqual(obj.value, "Test")

        data = obj.encode("Test")

        self.assertEqual("0x1054657374", data.to_hex())

    def test_string_multibyte_chars(self):
        obj = String.new()

        data = obj.encode('µ')
        self.assertEqual('0x08c2b5', data.to_hex())

        obj.decode(data)
        self.assertEqual(obj.value, "µ")

    def test_tuple(self):
        obj = Tuple(Compact(U32), Compact(U32)).new()
        obj.decode(ScaleBytes("0x0c00"))
        self.assertEqual(obj.value, (3, 0))

    def test_tuple_deserialize(self):
        obj = Tuple(Compact(U32), Compact(U32)).new()
        obj.deserialize((3, 2))
        self.assertEqual(obj.value, (3, 2))

    def test_balance(self):
        Balance = UnsignedInteger(128)
        obj = Compact(Balance).new()
        obj.decode(ScaleBytes("0x130080cd103d71bc22"))
        self.assertEqual(obj.value, 2503000000000000000)

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

    def test_dynamic_fixed_array_type_encode_u8(self):
        obj = Array(U8, 2).new()
        self.assertEqual('0x0102', str(obj.encode('0x0102')))
        self.assertEqual('0x0102', str(obj.encode(b'\x01\x02')))
        self.assertEqual('0x0102', str(obj.encode([1, 2])))

    def test_dynamic_fixed_array_type_encode(self):
        obj = Array(U32, 2).new()
        self.assertEqual('0x0100000002000000', str(obj.encode([1, 2])))

        obj = Array(U8, 3).new()
        self.assertEqual('0x010203', str(obj.encode('0x010203')))

    def test_invalid_fixed_array_type_encode(self):
        obj = Array(U8, 3).new()
        self.assertRaises(ScaleEncodeException, obj.encode, '0x0102')

        obj = Array(U32, 3).new()
        self.assertRaises(ScaleEncodeException, obj.encode, '0x0102')



    def test_ss58_encode_index(self):
        self.assertEqual(ss58_encode_account_index(0), 'F7Hs')

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

    def test_hashmap_encode(self):
        obj = HashMap(String, U32).new()
        data = obj.encode([('1', 2), ('23', 24), ('28', 30), ('45', 80)])
        self.assertEqual(data.to_hex(), '0x10043102000000083233180000000832381e00000008343550000000')

    def test_hashmap_decode(self):
        obj = HashMap(String, U32).new()
        data = ScaleBytes("0x10043102000000083233180000000832381e00000008343550000000")
        self.assertEqual([('1', 2), ('23', 24), ('28', 30), ('45', 80)], obj.decode(data))

