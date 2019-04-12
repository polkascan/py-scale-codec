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
import datetime
import unittest

from scalecodec.base import ScaleDecoder, ScaleBytes, RemainingScaleBytesNotEmptyException, \
    InvalidScaleTypeValueException


class TestScaleTypes(unittest.TestCase):

    def test_compact_u32(self):
        obj = ScaleDecoder.get_decoder_class('Compact<u32>', ScaleBytes("0x02093d00"))
        obj.decode()
        self.assertEqual(obj.value, 1000000)

    def test_compact_u32_1byte(self):
        obj = ScaleDecoder.get_decoder_class('Compact<u32>', ScaleBytes("0x18"))
        obj.decode()
        self.assertEqual(obj.value, 6)

    def test_compact_u32_remaining_bytes(self):
        obj = ScaleDecoder.get_decoder_class('Compact<u32>', ScaleBytes("0x02093d0001"))
        self.assertRaises(RemainingScaleBytesNotEmptyException, obj.decode)

    def test_compact_bool_true(self):
        obj = ScaleDecoder.get_decoder_class('bool', ScaleBytes("0x01"))
        obj.decode()
        self.assertEqual(obj.value, True)

    def test_compact_bool_false(self):
        obj = ScaleDecoder.get_decoder_class('bool', ScaleBytes("0x00"))
        obj.decode()
        self.assertEqual(obj.value, False)

    def test_compact_bool_invalid(self):
        obj = ScaleDecoder.get_decoder_class('bool', ScaleBytes("0x02"))
        self.assertRaises(InvalidScaleTypeValueException, obj.decode)

    def test_vec_accountid(self):
        obj = ScaleDecoder.get_decoder_class(
            'Vec<AccountId>',
            ScaleBytes("0x0865d2273adeb04478658e183dc5edf41f1d86e42255442af62e72dbf1e6c0b97765d2273adeb04478658e183dc5edf41f1d86e42255442af62e72dbf1e6c0b977")
        )
        obj.decode()
        self.assertListEqual(obj.value, [
            '0x65d2273adeb04478658e183dc5edf41f1d86e42255442af62e72dbf1e6c0b977',
            '0x65d2273adeb04478658e183dc5edf41f1d86e42255442af62e72dbf1e6c0b977'
        ])

    def test_validatorprefs_struct(self):
        obj = ScaleDecoder.get_decoder_class('ValidatorPrefs', ScaleBytes("0x0c00"))
        obj.decode()
        self.assertEqual(obj.value, {"col1": 3, "col2": 0})

    def test_implied_struct(self):
        obj = ScaleDecoder.get_decoder_class('(Compact<u32>,Compact<u32>)', ScaleBytes("0x0c00"))
        obj.decode()
        self.assertEqual(obj.value, {"col1": 3, "col2": 0})

    def test_address(self):
        obj = ScaleDecoder.get_decoder_class(
            'Address',
            ScaleBytes("0xff1fa9d1bd1db014b65872ee20aee4fd4d3a942d95d3357f463ea6c799130b6318")
        )
        obj.decode()
        self.assertEqual(obj.value, '1fa9d1bd1db014b65872ee20aee4fd4d3a942d95d3357f463ea6c799130b6318')

    def test_moment(self):
        obj = ScaleDecoder.get_decoder_class('Compact<Moment>', ScaleBytes("0x03d68b655c"))
        obj.decode()
        self.assertEqual(obj.value, datetime.datetime(2019, 2, 14, 15, 40, 6))

    def test_balance(self):
        obj = ScaleDecoder.get_decoder_class('Compact<Balance>', ScaleBytes("0x130080cd103d71bc22"))
        obj.decode()
        self.assertEqual(obj.value, 2503000000000000000)

    def test_unknown_decoder_class(self):
        self.assertRaises(NotImplementedError, ScaleDecoder.get_decoder_class, 'UnknownType123', ScaleBytes("0x0c00"))


    # TODO make type_index in Metadatadecoder and add tests if all types are supported
