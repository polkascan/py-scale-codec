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
from scalecodec.types import String, Bytes


class TestBytes(unittest.TestCase):

    def test_bytes_encode_decode(self):
        scale_obj = Bytes.new()
        value = "0x1274657374"

        data = scale_obj.encode(value)
        scale_obj.decode(data)

        self.assertEqual(value, scale_obj.value)

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

if __name__ == '__main__':
    unittest.main()
