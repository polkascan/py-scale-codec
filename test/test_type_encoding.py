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

import unittest

from scalecodec.base import ScaleBytes, ScaleDecoder, RuntimeConfiguration
from scalecodec.metadata import MetadataDecoder
from scalecodec.type_registry import load_type_registry_preset

from scalecodec.types import CompactU32, Vec
from test.fixtures import kusama_metadata_hex


class TestScaleTypeEncoding(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        RuntimeConfiguration().update_type_registry(load_type_registry_preset("default"))
        cls.metadata_decoder = MetadataDecoder(ScaleBytes(kusama_metadata_hex))
        cls.metadata_decoder.decode()

    def setUp(self) -> None:
        RuntimeConfiguration().update_type_registry(load_type_registry_preset("kusama"))

    def tearDown(self) -> None:
        RuntimeConfiguration().clear_type_registry()
        RuntimeConfiguration().update_type_registry(load_type_registry_preset("default"))

    def test_u16(self):
        obj = ScaleDecoder.get_decoder_class('u16')
        obj.encode(64302)
        self.assertEqual(str(obj.data), "0x2efb")

    def test_i16(self):
        obj = ScaleDecoder.get_decoder_class('i16')
        obj.encode(-1234)
        self.assertEqual(str(obj.data), "0x2efb")

    def test_i16_out_of_bounds(self):
        obj = ScaleDecoder.get_decoder_class('i16')
        self.assertRaises(ValueError, obj.encode, -32769)

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

    def test_struct_encode_decode(self):

        value = {'unstakeThreshold': 3, 'validatorPayment': 0}
        scale_data = ScaleBytes("0x0c00")

        obj = ScaleDecoder.get_decoder_class('ValidatorPrefsLegacy')
        data = obj.encode(value)

        self.assertEqual(str(scale_data), str(data))

        obj_check = ScaleDecoder.get_decoder_class('ValidatorPrefsLegacy', data)

        self.assertEqual(obj_check.decode(), value)

    def test_enum_encode_decode(self):

        value = {'Staked': None}

        obj = ScaleDecoder.get_decoder_class('RewardDestination')
        data = obj.encode(value)

        obj_check = ScaleDecoder.get_decoder_class('RewardDestination', data)

        self.assertEqual(obj_check.decode(), value)

    def test_enum_type_mapping_encode_decode(self):
        RuntimeConfiguration().update_type_registry(load_type_registry_preset("test"))

        value = {"AuthoritiesChange": ["0x586cb27c291c813ce74e86a60dad270609abf2fc8bee107e44a80ac00225c409"]}

        obj = ScaleDecoder.get_decoder_class('DigestItem')
        data = obj.encode(value)

        obj_check = ScaleDecoder.get_decoder_class('DigestItem', data)

        self.assertEqual(obj_check.decode(), value)

    def test_option_empty_encode_decode(self):

        value = None

        obj = ScaleDecoder.get_decoder_class('Option<Bytes>')
        data = obj.encode(value)

        obj_check = ScaleDecoder.get_decoder_class('Option<Bytes>', data)

        self.assertEqual(obj_check.decode(), value)

    def test_option_bytes_encode_decode(self):
        value = "Test"

        obj = ScaleDecoder.get_decoder_class('Option<Bytes>')
        data = obj.encode(value)

        obj_check = ScaleDecoder.get_decoder_class('Option<Bytes>', data)

        self.assertEqual(obj_check.decode(), value)

    def test_proposal_encode_decode(self):

        value = {
            'call_module': 'System',
            'call_function': 'remark',
            'call_args': {
                '_remark': '0x0123456789'
            }
        }

        obj = ScaleDecoder.get_decoder_class('Box<Proposal>', metadata=self.metadata_decoder)
        data = obj.encode(value)

        obj_check = ScaleDecoder.get_decoder_class('Box<Proposal>', data, metadata=self.metadata_decoder)

        obj_check.decode()

        self.assertEqual(obj_check.value['call_module'], 'System')
        self.assertEqual(obj_check.value['call_function'], 'remark')
        self.assertEqual(obj_check.value['call_args'][0]['value'], '0x0123456789')

    def test_set_encode_decode(self):

        RuntimeConfiguration().update_type_registry(load_type_registry_preset("test"))

        value = ['Display', 'Legal', 'Email', 'Twitter']

        obj = ScaleDecoder.get_decoder_class('IdentityFields')
        scale_data = obj.encode(value)

        obj = ScaleDecoder.get_decoder_class('IdentityFields', scale_data)
        obj.decode()

        self.assertEqual(obj.value, value)

    def test_data_encode_decode(self):

        value = {"Raw": "Test"}

        obj = ScaleDecoder.get_decoder_class('Data')
        scale_data = obj.encode(value)

        obj = ScaleDecoder.get_decoder_class('Data', scale_data)
        obj.decode()

        self.assertEqual(obj.value, value)

    def test_multi_encode(self):

        as_multi = ScaleDecoder.get_decoder_class("Call", metadata=self.metadata_decoder)

        as_multi.encode(
            {
                "call_module": "Multisig",
                "call_function": "as_multi",
                "call_args": {
                    "call": {
                        "call_module": "Balances",
                        "call_function": "transfer",
                        "call_args": {
                            "dest": "CofvaLbP3m8PLeNRQmLVPWmTT7jGgAXTwyT69k2wkfPxJ9V",
                            "value": 10000000000000
                        },
                    },
                    "maybe_timepoint": {"height": 3012294, "index": 3},
                    "other_signatories": sorted(['D2bHQwFcQj11SvtkjULEdKhK4WAeP6MThXgosMHjW9DrmbE',
                                                 'CofvaLbP3m8PLeNRQmLVPWmTT7jGgAXTwyT69k2wkfPxJ9V']),
                    "threshold": 2,
                    "store_call": True,
                    "max_weight": 10,
                },
            }
        )
        self.assertEqual(str(as_multi.data), "0x1f010200080a2ee2acc37fa96e818e2817afc104ce55770bcccb7333bbf8481d5bc3c6fa4614097421065c7bb0efc6770ffc5d604654159d45910cc7a3cb602be16acc552801c6f62d0003000000a80400000a2ee2acc37fa96e818e2817afc104ce55770bcccb7333bbf8481d5bc3c6fa460b00a0724e1809010a00000000000000")

    def test_call_encode_invalid_type(self):
        call = ScaleDecoder.get_decoder_class("Call", metadata=self.metadata_decoder)
        self.assertRaises(TypeError, call.encode, '{"call_module": "Balances", "call_function": "transfer"}')
        self.assertRaises(TypeError, call.encode, 2)

    def test_era_immortal_encode(self):
        obj = ScaleDecoder.get_decoder_class('Era')
        obj.encode('00')
        self.assertEqual(str(obj.data), '0x00')

    def test_era_mortal_encode(self):
        obj = ScaleDecoder.get_decoder_class('Era')
        obj.encode((32768, 20000))
        self.assertEqual(str(obj.data), '0x4e9c')

        obj = ScaleDecoder.get_decoder_class('Era')
        obj.encode((64, 60))
        self.assertEqual(str(obj.data), '0xc503')

        obj = ScaleDecoder.get_decoder_class('Era')
        obj.encode((64, 40))
        self.assertEqual(str(obj.data), '0x8502')

    def test_era_mortal_encode_dict(self):
        obj = ScaleDecoder.get_decoder_class('Era')
        obj.encode({'period': 32768, 'phase': 20000})
        self.assertEqual(str(obj.data), '0x4e9c')

        obj = ScaleDecoder.get_decoder_class('Era')
        obj.encode({'period': 32768, 'current': (32768 * 3) + 20000})
        self.assertEqual(str(obj.data), '0x4e9c')

        obj = ScaleDecoder.get_decoder_class('Era')
        obj.encode({'period': 200, 'current': 1400})
        obj2 = ScaleDecoder.get_decoder_class('Era')
        obj2.encode((256, 120))
        self.assertEqual(str(obj.data), str(obj2.data))
