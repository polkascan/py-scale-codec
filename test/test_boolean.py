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
from scalecodec.exceptions import ScaleDecodeException
from scalecodec.types import Bool


class TestBoolean(unittest.TestCase):

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

    def test_bool_encode_decode(self):
        scale_obj = Bool().new()
        value = True

        data = scale_obj.encode(value)
        scale_obj.decode(data)

        self.assertEqual(value, scale_obj.value)

    def test_bool_encode_false(self):
        scale_obj = Bool().new()
        data = scale_obj.encode(False)
        self.assertEqual(ScaleBytes("0x00"), data)


if __name__ == '__main__':
    unittest.main()
