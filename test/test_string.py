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
from scalecodec.types import String


class TestString(unittest.TestCase):

    def test_string_decode_encode(self):
        obj = String.new()
        obj.decode(ScaleBytes("0x1054657374"))
        self.assertEqual(obj.value, "Test")

        data = obj.encode("Test")

        self.assertEqual("0x1054657374", data.to_hex())

    def test_string_encode_decode(self):

        value = 'This is a test'

        obj = String.new()
        data = obj.encode(value)

        obj_check = String.new()

        self.assertEqual(obj_check.decode(data), value)

    def test_string_multibyte_chars(self):
        obj = String.new()

        data = obj.encode('µ')
        self.assertEqual('0x08c2b5', data.to_hex())

        obj.decode(data)
        self.assertEqual(obj.value, "µ")


if __name__ == '__main__':
    unittest.main()
