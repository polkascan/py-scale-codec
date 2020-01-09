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

from scalecodec.types import CompactU32, Vec


class TestScaleTypeEncoding(unittest.TestCase):

    def test_compact_u32_1byte(self):
        obj = ScaleDecoder.get_decoder_class('Compact<u32>', ScaleBytes("0x18"))
        obj.decode()

        obj = ScaleDecoder.get_decoder_class('Compact<u32>')
        obj.encode(6)
        self.assertEqual(str(obj.data), "0x18")

    def test_compact_u32_2bytes(self):
        obj = ScaleDecoder.get_decoder_class('Compact<u32>', ScaleBytes("0x18"))
        obj.decode()

        obj = ScaleDecoder.get_decoder_class('Compact<u32>')
        obj.encode(6000)
        self.assertEqual(str(obj.data), "0xc15d")

    def test_compact_u32_4bytes(self):

        obj = ScaleDecoder.get_decoder_class('Compact<u32>')
        obj.encode(1000000)
        self.assertEqual(str(obj.data), "0x02093d00")

    def test_compact_u32_larger_than_4bytes(self):

        obj = ScaleDecoder.get_decoder_class('Compact<u32>')
        obj.encode(150000000000000)
        self.assertEqual(str(obj.data), "0x0b0060b7986c88")

    def test_compact_u32_encode_decode(self):

        value = 2000001

        obj = ScaleDecoder.get_decoder_class('Compact<u32>')
        data = obj.encode(value)

        obj = CompactU32(data)

        self.assertEqual(obj.decode(), value)

    def test_compact_u32_encode_decode_large(self):

        value = 2**30

        obj = CompactU32(ScaleBytes(bytearray()))
        data = obj.encode(value)

        obj = CompactU32(data)

        self.assertEqual(obj.decode(), value)

    def test_vec_string_encode_decode(self):

        value = ['test', 'vec']

        obj = ScaleDecoder.get_decoder_class('Vec<Bytes>')
        data = obj.encode(value)

        obj = ScaleDecoder.get_decoder_class('Vec<Bytes>', data)

        self.assertEqual(obj.decode(), value)

    def test_vec_accountid_encode_decode(self):

        value = [
            '0x0034d9d2dcdcd79451d95fd019a056d47dfa9926d762b94e63f06391b1545aee',
            '0x2ce1929ab903f695bdeeeb79a588774d71468362129136f1b7f7b31a32958f98',
            '0x88c47944e4aaf9d53a9627400f9a948bb5f355bda38702dbdeda0c5d34553128',
        ]

        obj = ScaleDecoder.get_decoder_class('Vec<AccountId>')
        data = obj.encode(value)

        obj = ScaleDecoder.get_decoder_class('Vec<AccountId>', data)

        self.assertEqual(obj.decode(), value)

    def test_bytes_encode_decode(self):

        value = 'This is a test'

        obj = ScaleDecoder.get_decoder_class('Bytes')
        data = obj.encode(value)

        obj_check = ScaleDecoder.get_decoder_class('Bytes', data)

        self.assertEqual(obj_check.decode(), value)

    def test_hexbytes_encode_decode(self):

        value = '0x5468697320697320612074657374'

        obj = ScaleDecoder.get_decoder_class('HexBytes')
        data = obj.encode(value)

        obj_check = ScaleDecoder.get_decoder_class('HexBytes', data)

        self.assertEqual(obj_check.decode(), value)

    def test_accountid_encode_decode(self):
        value = '0x586cb27c291c813ce74e86a60dad270609abf2fc8bee107e44a80ac00225c409'

        obj = ScaleDecoder.get_decoder_class('AccountId')
        data = obj.encode(value)

        obj_check = ScaleDecoder.get_decoder_class('AccountId', data)

        self.assertEqual(obj_check.decode(), value)

    def test_compact_balance_encode_decode(self):
        scale_data = ScaleBytes('0x070010a5d4e8')
        value = 1000000000000

        obj = ScaleDecoder.get_decoder_class('Compact<Balance>')
        data = obj.encode(value)

        self.assertEqual(str(scale_data), str(data))

        obj_check = ScaleDecoder.get_decoder_class('Compact<Balance>', data)

        self.assertEqual(obj_check.decode(), value)


if __name__ == '__main__':
    unittest.main()
