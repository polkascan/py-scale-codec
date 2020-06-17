# Python SCALE Codec Library
#
# Copyright 2018-2020 openAware BV (NL).
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

from scalecodec.metadata import MetadataDecoder

from scalecodec.base import ScaleDecoder, ScaleBytes, RemainingScaleBytesNotEmptyException, \
    InvalidScaleTypeValueException, RuntimeConfiguration
from scalecodec.type_registry import load_type_registry_preset
from scalecodec.utils.ss58 import ss58_encode
from test.fixtures import metadata_v10_hex


class TestScaleTypes(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        RuntimeConfiguration().update_type_registry(load_type_registry_preset("default"))
        RuntimeConfiguration().update_type_registry(load_type_registry_preset("kusama"))
        RuntimeConfiguration().set_active_spec_version_id(1045)

        cls.metadata_decoder = MetadataDecoder(ScaleBytes(metadata_v10_hex))
        cls.metadata_decoder.decode()

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

    def test_compact_u32_invalid(self):
        obj = ScaleDecoder.get_decoder_class('Compact<u32>', ScaleBytes("0x"))
        self.assertRaises(InvalidScaleTypeValueException, obj.decode)

    def test_u16(self):
        obj = ScaleDecoder.get_decoder_class('u16', ScaleBytes("0x2efb"))
        obj.decode()
        self.assertEqual(obj.value, 64302)

    def test_i16(self):
        obj = ScaleDecoder.get_decoder_class('i16', ScaleBytes("0x2efb"))
        obj.decode()
        self.assertEqual(obj.value, -1234)

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
        obj = ScaleDecoder.get_decoder_class('ValidatorPrefsLegacy', ScaleBytes("0x0c00"))
        obj.decode()
        self.assertEqual(obj.value, {'unstakeThreshold': 3, 'validatorPayment': 0})

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

    def test_type_registry(self):
        # Example type SpecificTestType only define in type registry 'default'
        self.assertRaises(NotImplementedError, ScaleDecoder.get_decoder_class, 'SpecificTestType', ScaleBytes("0x01000000"))

        RuntimeConfiguration().update_type_registry(load_type_registry_preset("test"))

        obj = ScaleDecoder.get_decoder_class('SpecificTestType', ScaleBytes("0x06000000"))
        obj.decode()
        self.assertEqual(obj.value, 6)

    def test_type_registry_overloading(self):
        # Type BlockNumber defined as U32 in type registry 'kusama'
        RuntimeConfiguration().update_type_registry(load_type_registry_preset("kusama"))

        obj = ScaleDecoder.get_decoder_class('BlockNumber', ScaleBytes("0x0000000000000001"))
        self.assertRaises(RemainingScaleBytesNotEmptyException, obj.decode)

        # Type BlockNumber changed to U64 in type registry 'test'
        RuntimeConfiguration().update_type_registry(load_type_registry_preset("test"))

        obj = ScaleDecoder.get_decoder_class('BlockNumber', ScaleBytes("0x0000000000000001"))
        obj.decode()
        self.assertEqual(obj.value, 72057594037927936)

    def test_unknown_decoder_class(self):
        self.assertRaises(NotImplementedError, ScaleDecoder.get_decoder_class, 'UnknownType123', ScaleBytes("0x0c00"))

    def test_dynamic_set(self):
        RuntimeConfiguration().update_type_registry(load_type_registry_preset("default"))

        obj = ScaleDecoder.get_decoder_class('WithdrawReasons', ScaleBytes("0x0100000000000000"))
        obj.decode()

        self.assertEqual(obj.value, ["TransactionPayment"])

        obj = ScaleDecoder.get_decoder_class('WithdrawReasons', ScaleBytes("0x0300000000000000"))
        obj.decode()

        self.assertEqual(obj.value, ["TransactionPayment", "Transfer"])

        obj = ScaleDecoder.get_decoder_class('WithdrawReasons', ScaleBytes("0x1600000000000000"))
        obj.decode()

        self.assertEqual(obj.value, ["Transfer", "Reserve", "Tip"])

    def test_set_value_type_u32(self):
        RuntimeConfiguration().update_type_registry(load_type_registry_preset("default"))

        # Create set type with u32
        RuntimeConfiguration().update_type_registry({
            "types": {
                "CustomU32Set": {
                    "type": "set",
                    "value_type": "u32",
                    "value_list": {
                        "Value1": 1,
                        "Value2": 2,
                        "Value3": 4,
                        "Value4": 8,
                        "Value5": 16
                    }
                }
            }
        })

        obj = ScaleDecoder.get_decoder_class('CustomU32Set', ScaleBytes("0x0100000000000000"))
        self.assertRaises(RemainingScaleBytesNotEmptyException, obj.decode)

        obj = ScaleDecoder.get_decoder_class('CustomU32Set', ScaleBytes("0x01000000"))
        obj.decode()

        self.assertEqual(obj.value, ["Value1"])

        obj = ScaleDecoder.get_decoder_class('CustomU32Set', ScaleBytes("0x03000000"))
        obj.decode()

        self.assertEqual(obj.value, ["Value1", "Value2"])

        obj = ScaleDecoder.get_decoder_class('CustomU32Set', ScaleBytes("0x16000000"))
        obj.decode()

        self.assertEqual(obj.value, ["Value2", "Value3", "Value5"])

    def test_box_call(self):
        RuntimeConfiguration().update_type_registry(load_type_registry_preset("default"))

        scale_value = ScaleBytes("0x0400ff6e57561de4b4e63f0af8bf336008252a9597e5cdcb7622c72de4ff39731c5402070010a5d4e8")

        obj = ScaleDecoder.get_decoder_class('Box<Call>', scale_value, metadata=self.metadata_decoder)
        value = obj.decode()

        self.assertEqual(value['call_function'], 'transfer')
        self.assertEqual(value['call_module'], 'Balances')
        self.assertEqual(value['call_args'][0]['value'], '0x6e57561de4b4e63f0af8bf336008252a9597e5cdcb7622c72de4ff39731c5402')
        self.assertEqual(value['call_args'][1]['value'], 1000000000000)

    def test_parse_subtype(self):
        RuntimeConfiguration().update_type_registry(load_type_registry_preset("default"))

        obj = ScaleDecoder.get_decoder_class('(BalanceOf, Vec<(AccountId, Data)>)')

        self.assertEqual(obj.type_mapping[0][1].lower(), "BalanceOf".lower())
        self.assertEqual(obj.type_mapping[1][1].lower(), "Vec<(AccountId, Data)>".lower())

        obj = ScaleDecoder.get_decoder_class('Vec<UncleEntryItem<BlockNumber, Hash, AccountId>>')

        self.assertEqual(obj.sub_type, "UncleEntryItem<BlockNumber, Hash, AccountId>".lower())

    def test_dynamic_fixed_array_type_decode(self):
        obj = ScaleDecoder.get_decoder_class('[u32; 1]', data=ScaleBytes("0x01000000"))
        self.assertEqual([1], obj.decode())

        obj = ScaleDecoder.get_decoder_class('[u32; 3]', data=ScaleBytes("0x010000000200000003000000"))
        self.assertEqual([1, 2, 3], obj.decode())

    def test_dynamic_fixed_array_type_decode_u8(self):
        obj = ScaleDecoder.get_decoder_class('[u8; 65]', data=ScaleBytes("0xc42b82d02bce3202f6a05d4b06d1ad46963d3be36fd0528bbe90e7f7a4e5fcd38d14234b1c9fcee920d76cfcf43b4ed5dd718e357c2bc1aae3a642975207e67f01"))
        self.assertEqual('0xc42b82d02bce3202f6a05d4b06d1ad46963d3be36fd0528bbe90e7f7a4e5fcd38d14234b1c9fcee920d76cfcf43b4ed5dd718e357c2bc1aae3a642975207e67f01', obj.decode())

    def test_dynamic_fixed_array_type_encode_u8(self):
        obj = ScaleDecoder.get_decoder_class('[u8; 1]')
        self.assertEqual('0x01', str(obj.encode('0x01')))

    def test_dynamic_fixed_array_type_encode(self):
        obj = ScaleDecoder.get_decoder_class('[u32; 1]')
        self.assertEqual('0x0100000002000000', str(obj.encode([1, 2])))

        # obj = ScaleDecoder.get_decoder_class('[u8; 3]', data=ScaleBytes("0x010203"))
        # self.assertEqual([1, 2, 3], obj.decode())

    def test_create_multi_sig_address(self):
        MultiAccountId = RuntimeConfiguration().get_decoder_class("MultiAccountId")

        multi_sig_account = MultiAccountId.create_from_account_list(
            ["CdVuGwX71W4oRbXHsLuLQxNPns23rnSSiZwZPN4etWf6XYo",
             "J9aQobenjZjwWtU2MsnYdGomvcYbgauCnBeb8xGrcqznvJc",
             "HvqnQxDQbi3LL2URh7WQfcmi8b2ZWfBhu7TEDmyyn5VK8e2"], 2)

        multi_sig_address = ss58_encode(multi_sig_account.value.replace('0x', ''), 2)

        self.assertEqual(multi_sig_address, "HFXXfXavDuKhLLBhFQTat2aaRQ5CMMw9mwswHzWi76m6iLt")

