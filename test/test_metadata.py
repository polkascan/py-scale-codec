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
import os
import unittest

from scalecodec.base import ScaleBytes
from scalecodec.type_registry import load_type_registry_preset, load_type_registry_file
from scalecodec.types import MetadataVersioned


class TestMetadataRegistry(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        module_path = os.path.dirname(__file__)
        cls.metadata_fixture_dict = load_type_registry_file(
            os.path.join(module_path, 'fixtures', 'metadata_hex.json')
        )

    def test_metadata_registry_decode_v14(self):
        metadata_obj = MetadataVersioned.new()

        metadata_obj.decode(ScaleBytes(self.metadata_fixture_dict['V14']))

        self.assertEqual(metadata_obj.value_object[1].index, 14)
        self.assertIsNotNone(metadata_obj.portable_registry)

        self.assertGreater(len(metadata_obj[1][1]['pallets']), 0)
        self.assertGreater(len(metadata_obj.value[1]['V14']['pallets']), 0)

        self.assertGreater(len(metadata_obj.get_signed_extensions().items()), 0)

    def test_metadata_registry_decode_v15(self):
        metadata_obj = MetadataVersioned.new()

        metadata_obj.decode(ScaleBytes(self.metadata_fixture_dict['V15']))
        self.assertEqual(metadata_obj.value_object[1].index, 15)
        self.assertIsNotNone(metadata_obj.portable_registry)

        self.assertGreater(len(metadata_obj[1][1]['pallets']), 0)
        self.assertGreater(len(metadata_obj.value[1]['V15']['pallets']), 0)

        self.assertGreater(len(metadata_obj.get_signed_extensions().items()), 0)

# class TestMetadataTypes(unittest.TestCase):
#
#     metadata_version = 'karura_test'
#
#     @classmethod
#     def setUpClass(cls):
#         cls.runtime_config = RuntimeConfigurationObject()
#         cls.runtime_config.update_type_registry(load_type_registry_preset("core"))
#
#         module_path = os.path.dirname(__file__)
#         cls.metadata_fixture_dict = load_type_registry_file(
#             os.path.join(module_path, 'fixtures', 'metadata_hex.json')
#         )
#
#         cls.metadata_obj = cls.runtime_config.create_scale_object(
#             "MetadataVersioned", data=ScaleBytes(cls.metadata_fixture_dict[cls.metadata_version])
#         )
#         cls.metadata_obj.decode()
#
#         cls.runtime_config.add_portable_registry(cls.metadata_obj)
#
#     def test_storage_function_type_decomposition_simple(self):
#         pallet = self.metadata_obj.get_metadata_pallet("System")
#         storage_function = pallet.get_storage_function("BlockHash")
#
#         param_type_string = storage_function.get_params_type_string()
#         param_type_obj = self.runtime_config.create_scale_object(param_type_string[0])
#
#         type_info = param_type_obj.generate_type_decomposition()
#         self.assertEqual('u32', type_info)
#
#     def test_storage_function_type_decomposition_complex(self):
#         pallet = self.metadata_obj.get_metadata_pallet("Tokens")
#         storage_function = pallet.get_storage_function("TotalIssuance")
#
#         param_type_string = storage_function.get_params_type_string()
#         param_type_obj = self.runtime_config.create_scale_object(param_type_string[0])
#
#         type_info = param_type_obj.generate_type_decomposition()
#         self.assertIn('Token', type_info)
#         self.assertEqual('ACA', type_info['Token'][0])


