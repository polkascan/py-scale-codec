# Python SCALE Codec Library
#
# Copyright 2018-2023 Stichting Polkascan (Polkascan Foundation).
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
from scalecodec.types import Struct, U8, Tuple, U16, Enum, U32, Bool, Option, Compact, Vec, Array, Bytes, String


class TestScaleTypes(unittest.TestCase):

    metadata_fixture_dict = {}
    metadata_decoder = None
    runtime_config_v14 = None
    metadata_v14_obj = None

    def test_u8(self):
        scale_obj = U8.new()
        value = 42

        data = scale_obj.encode(value)
        scale_obj.decode(data)

        self.assertEqual(value, scale_obj.value)

    def test_u16(self):
        scale_obj = U16.new()
        value = 64302

        data = scale_obj.encode(value)
        self.assertEqual(data, ScaleBytes("0x2efb"))
        scale_obj.decode(data)

        self.assertEqual(value, scale_obj.value)

    def test_bool(self):
        scale_obj = Bool.new()
        value = True

        data = scale_obj.encode(value)
        scale_obj.decode(data)

        self.assertEqual(value, scale_obj.value)

    def test_tuple(self):
        scale_obj = Tuple(U8, U8).new()
        value = (1, 5)

        data = scale_obj.encode(value)
        scale_obj.decode(data)

        self.assertEqual(value, scale_obj.value)

    def test_struct(self):
        scale_obj = Struct(test=U8, test2=Tuple(U8, U8)).new()
        value = {'test': 2, "test2": (1, 5)}

        data = scale_obj.encode(value)
        scale_obj.decode(data)

        self.assertEqual(value, scale_obj.value)

    def test_enum(self):
        scale_obj = Enum(Bool=Bool, Number=U32, None_=None).new()
        value = {'Bool': True}

        data = scale_obj.encode(value)
        scale_obj.decode(data)

        self.assertEqual(value, scale_obj.value)

        value = {'Number': 7643}

        data = scale_obj.encode(value)
        scale_obj.decode(data)

        self.assertEqual(value, scale_obj.value)

        value = 'None'

        data = scale_obj.encode(value)
        scale_obj.decode(data)

        self.assertEqual(value, scale_obj.value)

    def test_option(self):
        scale_obj = Option(U16).new()

        value = None

        data = scale_obj.encode(value)
        scale_obj.decode(data)

        self.assertEqual(value, scale_obj.value)

        value = 12788

        data = scale_obj.encode(value)
        scale_obj.decode(data)

        self.assertEqual(value, scale_obj.value)

    def test_compact(self):
        data = ScaleBytes("0x02093d00")
        compact = Compact().new()
        compact.decode(data)
        self.assertEqual(compact.value, 1000000)

        compact.encode(1000000)
        self.assertEqual(compact.data, data)

    def test_vec(self):

        obj = Vec(U8).new()

        value = [1, 2]
        data = obj.encode(value)

        self.assertEqual(data, ScaleBytes('0x080102'))
        self.assertEqual(value, obj.decode(data))

        self.assertEqual(obj.value_object[0].value, 1)
        self.assertEqual(obj.value_object[1].value, 2)

    def test_array(self):
        obj = Array(U8, 4).new()

        value = [1, 2, 3, 4]
        data = obj.encode(value)

        self.assertEqual(data, ScaleBytes('0x01020304'))

        data.reset()
        self.assertEqual('0x01020304', obj.decode(data))

        self.assertEqual(obj.value_object, b'\x01\x02\x03\x04')

    def test_bytes(self):
        scale_obj = Bytes().new()
        value = "0x74657374"

        data = scale_obj.encode(value)
        scale_obj.decode(data)

        self.assertEqual(value, scale_obj.value)

    def test_string(self):
        scale_obj = String().new()
        value = "test"

        data = scale_obj.encode(value)
        scale_obj.decode(data)

        self.assertEqual(value, scale_obj.value)

    def test_string_multibyte_chars(self):
        obj = String().new()

        data = obj.encode('µ')
        self.assertEqual('0x08c2b5', data.to_hex())

        obj.decode(data)
        self.assertEqual(obj.value, "µ")
