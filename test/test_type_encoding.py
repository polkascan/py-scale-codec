# Python SCALE Codec Library
#
# Copyright 2018-2019 openAware BV (NL).
# This file is part of Polkascan.
#
# Polkascan is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# Polkascan is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with Polkascan. If not, see <http://www.gnu.org/licenses/>.

import unittest

from scalecodec.base import ScaleBytes, ScaleDecoder

from scalecodec import CompactU32


class TestScaleTypeEncoding(unittest.TestCase):

    def test_compact_u32_1byte(self):
        obj = ScaleDecoder.get_decoder_class('Compact<u32>', ScaleBytes("0x18"))
        obj.decode()

        obj = CompactU32(ScaleBytes(bytearray()))
        obj.encode(6)
        self.assertEqual(str(obj.data), "0x18")

    def test_compact_u32_2bytes(self):
        obj = ScaleDecoder.get_decoder_class('Compact<u32>', ScaleBytes("0x18"))
        obj.decode()

        obj = CompactU32(ScaleBytes(bytearray()))
        obj.encode(6000)
        self.assertEqual(str(obj.data), "0xc15d")

    def test_compact_u32_4bytes(self):

        obj = CompactU32(ScaleBytes(bytearray()))
        obj.encode(1000000)
        self.assertEqual(str(obj.data), "0x02093d00")

    def test_compact_u32_larger_than_4bytes(self):

        obj = CompactU32(ScaleBytes(bytearray()))
        obj.encode(150000000000000)
        self.assertEqual(str(obj.data), "0x0b0060b7986c88")

    def test_compact_u32_encode_decode(self):

        value = 2000001

        obj = CompactU32(ScaleBytes(bytearray()))
        data = obj.encode(value)

        obj = CompactU32(data)

        self.assertEqual(obj.decode(), value)
