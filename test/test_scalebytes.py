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
#
#  test_scalebytes.py
#

import unittest

from scalecodec.base import ScaleBytes
from scalecodec.exceptions import RemainingScaleBytesNotEmptyException
from scalecodec.types import Compact, U32, Array, U8, String


class TestScaleBytes(unittest.TestCase):

    def test_unknown_data_format(self):
        self.assertRaises(ValueError, ScaleBytes, 123)
        self.assertRaises(ValueError, ScaleBytes, 'test')

    def test_bytes_data_format(self):
        obj = Compact(U32).new()
        obj.decode(ScaleBytes(b"\x02\x09\x3d\x00"))
        self.assertEqual(obj.value, 1000000)

    def test_remaining_bytes(self):
        scale = ScaleBytes("0x01020304")
        scale.get_next_bytes(1)
        self.assertEqual(scale.get_remaining_bytes(), b'\x02\x03\x04')

    def test_reset(self):
        scale = ScaleBytes("0x01020304")
        scale.get_next_bytes(1)
        scale.reset()
        self.assertEqual(scale.get_remaining_bytes(), b'\x01\x02\x03\x04')

    def test_add_scalebytes(self):
        scale_total = ScaleBytes("0x0102") + "0x0304"

        self.assertEqual(scale_total.data, bytearray.fromhex("01020304"))

    def test_scale_bytes_compare(self):
        self.assertEqual(ScaleBytes('0x1234'), ScaleBytes('0x1234'))
        self.assertNotEqual(ScaleBytes('0x1234'), ScaleBytes('0x555555'))

    def test_no_more_bytes_available(self):
        obj = Array(U8, 4).new()
        with self.assertRaises(RemainingScaleBytesNotEmptyException):
            obj.decode(ScaleBytes("0x010203"), check_remaining=False)

