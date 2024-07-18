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

import unittest

from scalecodec.base import ScaleBytes
from scalecodec.types import Compact, U32, U16, Tuple


class TestScaleTypes(unittest.TestCase):

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
