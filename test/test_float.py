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
from scalecodec.types import F64, F32


class TestFloat(unittest.TestCase):

    def test_f64_decode(self):
        obj = F64.new()
        obj.decode(ScaleBytes("0x333333333333f33f"))
        self.assertAlmostEqual(obj.value, 1.2)

    def test_f32_decode(self):
        obj = F32.new()
        obj.decode(ScaleBytes("0x9a99993f"))
        self.assertAlmostEqual(obj.value, 1.2)

    def test_f64_encode(self):
        obj = F64.new()
        obj.encode(-0.0)
        self.assertEqual(str(obj.data), "0x0000000000000080")

    def test_f64_encode_invalid_input(self):
        obj = F64.new()
        with self.assertRaises(ValueError) as cm:
            obj.encode(-0)
            self.assertEqual('0 is not a float', str(cm.exception))

    def test_f32_encode(self):
        obj = F32.new()
        obj.encode(-0.0)
        self.assertEqual(str(obj.data), "0x00000080")


if __name__ == '__main__':
    unittest.main()
