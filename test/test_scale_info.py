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
#  test_scale_info.py
#
import os
import unittest

from scalecodec.types import GenericAccountId, Null

from scalecodec.base import RuntimeConfigurationObject, ScaleDecoder, ScaleBytes

from scalecodec.metadata import TypeRegistry
from scalecodec.type_registry import load_type_registry_file, load_type_registry_preset


class ScaleInfoTestCase(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        module_path = os.path.dirname(__file__)

        scale_info_defaults = load_type_registry_file(os.path.join(module_path, 'fixtures', 'scale_info_defaults.json'))

        cls.runtime_config = RuntimeConfigurationObject(ss58_format=42)
        cls.runtime_config.update_type_registry(load_type_registry_preset("metadata_types"))
        cls.runtime_config.update_type_registry(scale_info_defaults)

        cls.metadata_fixture_dict = load_type_registry_file(
            os.path.join(module_path, 'fixtures', 'metadata_hex.json')
        )

        metadata_obj = ScaleDecoder.get_decoder_class(
            'MetadataVersioned', data=ScaleBytes(cls.metadata_fixture_dict['V14']), runtime_config=cls.runtime_config
        )
        metadata_obj.decode()

        cls.runtime_config.add_portable_registry(metadata_obj)

    def test_path_overrides(self):
        account_cls = self.runtime_config.get_decoder_class('scale_info::0')
        self.assertIsInstance(account_cls(), GenericAccountId)

    def test_primitives(self):
        # scale_info::2 = u8
        obj = ScaleDecoder.get_decoder_class(
            'scale_info::2', ScaleBytes("0x02"), runtime_config=self.runtime_config
        )
        obj.decode()
        self.assertEqual(obj.value, 2)

        # scale_info::64 = u16
        obj = ScaleDecoder.get_decoder_class(
            'scale_info::64', ScaleBytes("0x2efb"), runtime_config=self.runtime_config
        )
        obj.decode()
        self.assertEqual(obj.value, 64302)

    def test_compact(self):
        # scale_info::44 = compact<u32>
        obj = ScaleDecoder.get_decoder_class(
            'scale_info::44', ScaleBytes("0x02093d00"), runtime_config=self.runtime_config
        )
        obj.decode()
        self.assertEqual(obj.value, 1000000)

        # scale_info::100 = compact<u128>
        obj = ScaleDecoder.get_decoder_class(
            'scale_info::100', ScaleBytes("0x130080cd103d71bc22"), runtime_config=self.runtime_config
        )
        obj.decode()
        self.assertEqual(obj.value, 2503000000000000000)

    def test_array(self):
        # scale_info::14 = [u8; 4]
        obj = ScaleDecoder.get_decoder_class(
            'scale_info::14', ScaleBytes("0x01020304"),
            runtime_config=self.runtime_config
        )
        obj.decode()
        self.assertEqual(obj.value, "0x01020304")

    def test_enum(self):
        # ['sp_runtime', 'generic', 'digest', 'DigestItem']
        obj = ScaleDecoder.get_decoder_class(
            'scale_info::13', ScaleBytes("0x051054657374"), runtime_config=self.runtime_config
        )
        obj.decode()
        self.assertEqual({"Other": "Test"}, obj.value)

        obj.encode({'Other': "Test"})
        self.assertEqual(obj.data.to_hex(), "0x051054657374")

    def test_enum_multiple_fields(self):

        obj = ScaleDecoder.get_decoder_class(
            'scale_info::13', ScaleBytes("0x01010203041054657374"), runtime_config=self.runtime_config
        )
        obj.decode()

        self.assertEqual({'PreRuntime': ("0x01020304", "Test")}, obj.value)

    def test_enum_no_value(self):
        obj = ScaleDecoder.get_decoder_class(
            'scale_info::21', ScaleBytes("0x02"), runtime_config=self.runtime_config
        )
        obj.decode()
        self.assertEqual('CodeUpdated', obj.value)

    def test_named_struct(self):
        # scale_info::58 = ['frame_support', 'weights', 'RuntimeDbWeight']
        obj = ScaleDecoder.get_decoder_class(
            'scale_info::58',
            ScaleBytes("0xe110000000000000d204000000000000"),
            runtime_config=self.runtime_config
        )
        obj.decode()

        self.assertEqual(obj.value, {
            'read': 4321,
            'write': 1234
        })

        obj.encode({
            'read': 4321,
            'write': 1234
        })

        self.assertEqual(obj.data.to_hex(), '0xe110000000000000d204000000000000')

    def test_unnamed_struct_one_element(self):

        obj = ScaleDecoder.get_decoder_class(
            'scale_info::48',
            ScaleBytes("0x04000000"),
            runtime_config=self.runtime_config
        )
        obj.decode()

        self.assertEqual(obj.value, 4)

        obj.encode(5)

        self.assertEqual(obj.data.to_hex(), "0x05000000")

    def test_unnamed_struct_multiple_elements(self):
        # pallet_democracy::vote::PriorLock
        obj = ScaleDecoder.get_decoder_class(
            'scale_info::116',
            ScaleBytes("0x010c000000000000002200000000000000"),
            runtime_config=self.runtime_config
        )
        obj.decode()
        self.assertEqual(({'Mortal': (12, 34)}, None), obj.value)

        data = obj.encode(('Immortal', None))
        self.assertEqual(data.to_hex(), '0x00')

        data = obj.encode(({'Mortal': (12, 34)}, None))
        self.assertEqual(data.to_hex(), '0x010c000000000000002200000000000000')

    def test_tuple(self):
        obj = ScaleDecoder.get_decoder_class(
            'scale_info::42',
            ScaleBytes("0x0400000003000000"),
            runtime_config=self.runtime_config
        )
        obj.decode()

        self.assertEqual((4, 3), obj.value)

    def test_option(self):
        obj = ScaleDecoder.get_decoder_class(
            'scale_info::16',
            ScaleBytes("0x00"),
            runtime_config=self.runtime_config
        )
        obj.decode()

        self.assertIsNone(obj.value)

        data = obj.encode({'digest_interval': 100, 'digest_levels': 4})

        self.assertEqual('0x016400000004000000', data.to_hex())

    def test_option2(self):
        obj = ScaleDecoder.get_decoder_class(
            'scale_info::55',
            ScaleBytes("0x010000e941cc6b0100"),
            runtime_config=self.runtime_config
        )
        obj.decode()
        self.assertEqual(400000000000000, obj.value)

    def test_weak_bounded_vec(self):
        # 87 = ['frame_support', 'storage', 'weak_bounded_vec', 'WeakBoundedVec']
        obj = ScaleDecoder.get_decoder_class(
            'scale_info::87',
            ScaleBytes("0x0401020304050607080a00000000000000000000000000000000"),
            runtime_config=self.runtime_config
        )
        obj.decode()

        self.assertEqual([{"id": "0x0102030405060708", 'amount': 10, 'reasons': "Fee"}], obj.value)

        data = obj.encode([{"id": "0x0102030405060708", 'amount': 10, 'reasons': "Fee"}])
        self.assertEqual('0x0401020304050607080a00000000000000000000000000000000', data.to_hex())

    def test_bounded_vec(self):
        # 'scale_info::92' = frame_support::storage::bounded_vec::BoundedVec
        obj = ScaleDecoder.get_decoder_class(
            'scale_info::92',
            ScaleBytes("0x0401020304050607080a00000000000000000000000000000000"),
            runtime_config=self.runtime_config
        )

        data = obj.encode([{"id": "0x0102030405060708", 'amount': 10}])
        self.assertEqual('0x0401020304050607080a000000000000000000000000000000', data.to_hex())

        obj.decode()
        self.assertEqual([{"id": "0x0102030405060708", 'amount': 10}], obj.value)

    def test_phantom(self):
        phantom_obj = ScaleDecoder.get_decoder_class('scale_info::66', runtime_config=self.runtime_config)

        self.assertIsInstance(phantom_obj, Null)

    def test_unknown_scale_info_type(self):
        with self.assertRaises(NotImplementedError):
            self.runtime_config.update_from_scale_info_types([{'def': 'unknown'}])


# class PortableRegistryTestCase(unittest.TestCase):
#
#     def test_encode_dict_to_portable_registry(self):
#         runtime_config = RuntimeConfigurationObject()
#         runtime_config.update_type_registry(load_type_registry_preset("metadata_types"))
#
#         module_path = os.path.dirname(__file__)
#         metadata_dict = load_type_registry_file(os.path.join(module_path, 'fixtures', 'polkadot-metadata0.json'))
#
#         registry_obj = ScaleDecoder.get_decoder_class('PortableRegistry', runtime_config=runtime_config)
#
#         registry_obj.encode(metadata_dict[1]["V14"]['types'])
#
#         self.assertIsNotNone(registry_obj.value)
#
#         registry_obj.decode()
#
#         self.assertIsNotNone(registry_obj.value_object)


if __name__ == '__main__':
    unittest.main()
