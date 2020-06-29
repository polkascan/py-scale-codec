#  Polkascan Substrate Interface GUI
#
#  Copyright 2018-2020 openAware BV (NL).
#  This file is part of Polkascan.
#
#  Polkascan is free software: you can redistribute it and/or modify
#  it under the terms of the GNU General Public License as published by
#  the Free Software Foundation, either version 3 of the License, or
#  (at your option) any later version.
#
#  Polkascan is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#  GNU General Public License for more details.
#
#  You should have received a copy of the GNU General Public License
#  along with Polkascan. If not, see <http://www.gnu.org/licenses/>.
#
#  test_scalebytes.py
#

import unittest

from scalecodec.base import ScaleDecoder, ScaleBytes
from scalecodec.exceptions import RemainingScaleBytesNotEmptyException


class TestScaleBytes(unittest.TestCase):

    def test_unknown_data_format(self):
        self.assertRaises(ValueError, ScaleBytes, 123)
        self.assertRaises(ValueError, ScaleBytes, 'test')

    def test_bytes_data_format(self):
        obj = ScaleDecoder.get_decoder_class('Compact<u32>', ScaleBytes(b"\x02\x09\x3d\x00"))
        obj.decode()
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

    def test_abstract_process(self):
        self.assertRaises(NotImplementedError, ScaleDecoder.process, None)

    def test_abstract_encode(self):
        self.assertRaises(NotImplementedError, ScaleDecoder.process_encode, None, None)

    def test_add_scalebytes(self):
        scale_total = ScaleBytes("0x0102") + "0x0304"

        self.assertEqual(scale_total.data, bytearray.fromhex("01020304"))

    def test_scale_decoder_remaining_bytes(self):
        obj = ScaleDecoder.get_decoder_class('[u8; 3]', ScaleBytes("0x010203"))
        self.assertEqual(obj.get_remaining_bytes(), b"\x01\x02\x03")

    def test_no_more_bytes_available(self):
        obj = ScaleDecoder.get_decoder_class('[u8; 4]', ScaleBytes("0x010203"))
        self.assertRaises(RemainingScaleBytesNotEmptyException, obj.decode, False)

    def test_str_representation(self):
        obj = ScaleDecoder.get_decoder_class('Bytes', ScaleBytes("0x1054657374"))
        obj.decode()
        self.assertEqual(str(obj), "Test")

    def test_type_convert(self):
        self.assertEqual(ScaleDecoder.convert_type("RawAddress"), "Address")
        self.assertEqual(ScaleDecoder.convert_type("<Balance as HasCompact>::Type"), "Compact<Balance>")
        self.assertEqual(ScaleDecoder.convert_type("<BlockNumber as HasCompact>::Type"), "Compact<BlockNumber>")
        self.assertEqual(ScaleDecoder.convert_type("<Moment as HasCompact>::Type"), "Compact<Moment>")

