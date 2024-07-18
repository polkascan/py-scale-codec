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

from scalecodec.types import Option, U16, Bytes, String


class TestOption(unittest.TestCase):

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


if __name__ == '__main__':
    unittest.main()
