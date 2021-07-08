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

from scalecodec.base import ScaleBytes, RuntimeConfiguration, ScaleDecoder, RuntimeConfigurationObject
from scalecodec.metadata import MetadataDecoder
from scalecodec.type_registry import load_type_registry_preset, load_type_registry_file


class TestMetadata(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        RuntimeConfiguration().clear_type_registry()
        RuntimeConfiguration().update_type_registry(load_type_registry_preset("default"))

        module_path = os.path.dirname(__file__)
        cls.metadata_fixture_dict = load_type_registry_file(
            os.path.join(module_path, 'fixtures', 'metadata_hex.json')
        )

    def test_metadata_v9(self):
        metadata_decoder = MetadataDecoder(ScaleBytes(self.metadata_fixture_dict['V9']))
        metadata_decoder.decode()
        self.assertEqual(metadata_decoder.version.value, "MetadataV9Decoder")

        for module in metadata_decoder.metadata.modules:
            if module.calls:
                for call in module.calls:
                    for arg in call.args:
                        decoder_class = ScaleDecoder.get_decoder_class(arg.type)
                        self.assertIsNotNone(decoder_class, msg='{} is not supported by metadata'.format(arg.type))

    def test_metadata_v10(self):
        metadata_decoder = MetadataDecoder(ScaleBytes(self.metadata_fixture_dict['V10']))
        metadata_decoder.decode()
        self.assertEqual(metadata_decoder.version.value, "MetadataV10Decoder")

        for module in metadata_decoder.metadata.modules:
            if module.calls:
                for call in module.calls:
                    for arg in call.args:
                        decoder_class = ScaleDecoder.get_decoder_class(arg.type)
                        self.assertIsNotNone(decoder_class, msg='{} is not supported by metadata'.format(arg.type))

    def test_metadata_v11(self):
        metadata_decoder = MetadataDecoder(ScaleBytes(self.metadata_fixture_dict['V11']))
        metadata_decoder.decode()
        self.assertEqual(metadata_decoder.version.value, "MetadataV11Decoder")

        for module in metadata_decoder.metadata.modules:
            if module.calls:
                for call in module.calls:
                    for arg in call.args:
                        decoder_class = ScaleDecoder.get_decoder_class(arg.type)
                        self.assertIsNotNone(decoder_class, msg='{} is not supported by metadata'.format(arg.type))

    def test_metadata_v12(self):
        metadata_decoder = MetadataDecoder(ScaleBytes(self.metadata_fixture_dict['V12']))
        metadata_decoder.decode()
        self.assertEqual(metadata_decoder.version.value, "MetadataV12Decoder")

        for module in metadata_decoder.metadata.modules:
            if module.calls:
                for call in module.calls:
                    for arg in call.args:
                        decoder_class = ScaleDecoder.get_decoder_class(arg.type)
                        self.assertIsNotNone(decoder_class, msg='{} is not supported by metadata'.format(arg.type))

    def test_metadata_v13(self):
        metadata_decoder = MetadataDecoder(ScaleBytes(self.metadata_fixture_dict['V13']))
        metadata_decoder.decode()
        self.assertEqual(metadata_decoder.version.value, "MetadataV13Decoder")

        for module in metadata_decoder.metadata.modules:
            if module.calls:
                for call in module.calls:
                    for arg in call.args:
                        decoder_class = ScaleDecoder.get_decoder_class(arg.type)
                        self.assertIsNotNone(decoder_class, msg='{} is not supported by metadata'.format(arg.type))


class TestMetadataRegistry(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.runtime_config = RuntimeConfigurationObject()
        cls.runtime_config.update_type_registry(load_type_registry_preset("metadata_types"))

        module_path = os.path.dirname(__file__)
        cls.metadata_fixture_dict = load_type_registry_file(
            os.path.join(module_path, 'fixtures', 'metadata_hex.json')
        )

    def test_metadata_registry_v13(self):

        metadata_obj = ScaleDecoder.get_decoder_class(
            "MetadataVersioned", data=ScaleBytes(self.metadata_fixture_dict['V13']), runtime_config=self.runtime_config
        )
        metadata_obj.decode()
        self.assertEqual(metadata_obj.value_object[1].index, 13)
        self.assertGreater(len(metadata_obj.value[1]['V13']['modules']), 0)
        self.assertGreater(len(metadata_obj.call_index.items()), 0)

    # def test_metadata_registry_encode_v14(self):
    #
    #     module_path = os.path.dirname(__file__)
    #     metadata_dict = load_type_registry_file(os.path.join(module_path, 'fixtures', 'polkadot-metadata0.json'))
    #     metadata_dict[0] = '0x6d657461'
    #
    #     metadata_obj = ScaleDecoder.get_decoder_class('MetadataVersioned', runtime_config=self.runtime_config)
    #     metadata_obj.encode(metadata_dict)
    #     metadata_obj.decode()
    #
    #     self.assertIsNotNone(metadata_obj.value)

    def test_metadata_registry_decode_v14(self):
        metadata_obj = ScaleDecoder.get_decoder_class(
            "MetadataVersioned", data=ScaleBytes(self.metadata_fixture_dict['V14']), runtime_config=self.runtime_config
        )
        metadata_obj.decode()
        self.assertEqual(metadata_obj.value_object[1].index, 14)
        self.assertGreater(len(metadata_obj.value[1]['V14']['pallets']), 0)
        self.assertGreater(len(metadata_obj.call_index.items()), 0)


