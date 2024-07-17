#  Polkascan API extension for Substrate Interface Library
#
#  Copyright 2018-2024 Stichting Polkascan (Polkascan Foundation).
#
#  Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at
#
#  http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.
#

import unittest

from scalecodec.base import ScaleBytes
from scalecodec.exceptions import ScaleDeserializeException, ScaleEncodeException, ScaleDecodeException
from scalecodec.types import Struct, U8, Tuple, U32


class TestStruct(unittest.TestCase):

    def test_struct_encode(self):

        scale_obj = Struct(test=U8, test2=Tuple(U8, U8)).new()
        value = {'test': 2, "test2": (1, 5)}

        data = scale_obj.encode(value)

        self.assertEqual(ScaleBytes(data="0x020105"), data)

    def test_struct_encode2(self):

        obj = Struct(aye=U32, nay=U32).new()
        data = obj.encode({'aye': 4, 'nay': 2})

        self.assertEqual(ScaleBytes("0x0400000002000000"), data)

    def test_struct_encode_tuple(self):

        obj = Struct(aye=U32, nay=U32).new()
        data = obj.encode((4, 2))

        self.assertEqual(ScaleBytes("0x0400000002000000"), data)

    def test_struct_encode_int(self):

        obj = Struct(nonce=U32).new()
        data = obj.encode({'nonce': 1})

        self.assertEqual(ScaleBytes("0x01000000"), data)

    def test_struct_subclass(self):

        class Votes(Struct):
            arguments = {'aye': U32, 'nay': U32}

        obj = Votes().new()

        data = obj.encode({'aye': 4, 'nay': 2})

        self.assertEqual(ScaleBytes("0x0400000002000000"), data)

    def test_encode_missing_data(self):
        scale_obj = Struct(test=U8, test2=Tuple(U8, U8)).new()
        with self.assertRaises(ScaleEncodeException) as e:
            scale_obj.encode({'test': 2, "test3": (1, 5)})

    def test_decode(self):
        scale_obj = Struct(test=U8, test2=Tuple(U8, U8)).new()

        scale_obj.decode(ScaleBytes(data="0x020105"))
        self.assertDictEqual({'test': 2, "test2": (1, 5)}, scale_obj.value)

    def test_decode_remaining(self):
        scale_obj = Struct(test=U8, test2=Tuple(U8, U8)).new()

        with self.assertRaises(ScaleDecodeException) as e:
            scale_obj.decode(ScaleBytes(data="0x02010501"), check_remaining=True)

    def test_deserialize(self):
        scale_obj = Struct(test=U8, test2=Tuple(U8, U8)).new()
        scale_obj.deserialize({'test': 2, "test2": (1, 5)})

        self.assertIn('test', scale_obj.value_object)
        self.assertIn('test2', scale_obj.value_object)

    def test_deserialize_missing_data(self):
        scale_obj = Struct(test=U8, test2=Tuple(U8, U8)).new()
        with self.assertRaises(ScaleDeserializeException) as e:
            scale_obj.deserialize({'test': 2, "test3": (1, 5)})


if __name__ == '__main__':
    unittest.main()
