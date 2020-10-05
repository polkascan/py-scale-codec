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

from scalecodec.base import ScaleBytes, RuntimeConfiguration, ScaleDecoder
from scalecodec.metadata import MetadataDecoder
from scalecodec.type_registry import load_type_registry_preset
from test.fixtures import metadata_v3_hex, metadata_v2_hex, metadata_v1_hex, invalid_metadata_v1_hex, metadata_v12_hex, \
    metadata_v11_hex, metadata_v10_hex, metadata_v9_hex


class TestMetadata(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        RuntimeConfiguration().clear_type_registry()
        RuntimeConfiguration().update_type_registry(load_type_registry_preset("default"))

    def test_decode_metadata_v3(self):
        metadata_decoder = MetadataDecoder(ScaleBytes(metadata_v3_hex))
        metadata_decoder.decode()
        self.assertEqual(metadata_decoder.version.value, "MetadataV3Decoder")

    def test_decode_metadata_v2(self):
        metadata_decoder = MetadataDecoder(ScaleBytes(metadata_v2_hex))
        metadata_decoder.decode()
        self.assertEqual(metadata_decoder.version.value, "MetadataV2Decoder")

    def test_decode_metadata_v1(self):
        metadata_decoder = MetadataDecoder(ScaleBytes(metadata_v1_hex))
        metadata_decoder.decode()
        self.assertEqual(metadata_decoder.version.value, "MetadataV1Decoder")

    def test_decode_invalid_metadata_v1(self):
        metadata_decoder = MetadataDecoder(ScaleBytes(invalid_metadata_v1_hex))
        self.assertRaises(Exception, metadata_decoder.decode)

    def test_all_scale_type_supported_v1(self):
        metadata_decoder = MetadataDecoder(ScaleBytes(metadata_v1_hex))
        metadata_decoder.decode()
        self.assertEqual(metadata_decoder.version.value, "MetadataV1Decoder")

        for module in metadata_decoder.metadata.modules:
            if module.calls:
                for call in module.calls:
                    for arg in call.args:
                        decoder_class = ScaleDecoder.get_decoder_class(arg.type)
                        self.assertIsNotNone(decoder_class, msg='{} is not supported by metadata'.format(arg.type))

    def test_all_scale_type_supported_v2(self):
        metadata_decoder = MetadataDecoder(ScaleBytes(metadata_v2_hex))
        metadata_decoder.decode()
        self.assertEqual(metadata_decoder.version.value, "MetadataV2Decoder")

        for module in metadata_decoder.metadata.modules:
            if module.calls:
                for call in module.calls:
                    for arg in call.args:
                        decoder_class = ScaleDecoder.get_decoder_class(arg.type)
                        self.assertIsNotNone(decoder_class, msg='{} is not supported by metadata'.format(arg.type))

    def test_all_scale_type_supported_v3(self):
        metadata_decoder = MetadataDecoder(ScaleBytes(metadata_v3_hex))
        metadata_decoder.decode()
        self.assertEqual(metadata_decoder.version.value, "MetadataV3Decoder")

        for module in metadata_decoder.metadata.modules:
            if module.calls:
                for call in module.calls:
                    for arg in call.args:
                        decoder_class = ScaleDecoder.get_decoder_class(arg.type)
                        self.assertIsNotNone(decoder_class, msg='{} is not supported by metadata'.format(arg.type))

    def test_metadata_v9(self):
        metadata_decoder = MetadataDecoder(ScaleBytes(metadata_v9_hex))
        metadata_decoder.decode()
        self.assertEqual(metadata_decoder.version.value, "MetadataV9Decoder")

        for module in metadata_decoder.metadata.modules:
            if module.calls:
                for call in module.calls:
                    for arg in call.args:
                        decoder_class = ScaleDecoder.get_decoder_class(arg.type)
                        self.assertIsNotNone(decoder_class, msg='{} is not supported by metadata'.format(arg.type))

    def test_metadata_v10(self):
        metadata_decoder = MetadataDecoder(ScaleBytes(metadata_v10_hex))
        metadata_decoder.decode()
        self.assertEqual(metadata_decoder.version.value, "MetadataV10Decoder")

        for module in metadata_decoder.metadata.modules:
            if module.calls:
                for call in module.calls:
                    for arg in call.args:
                        decoder_class = ScaleDecoder.get_decoder_class(arg.type)
                        self.assertIsNotNone(decoder_class, msg='{} is not supported by metadata'.format(arg.type))

    def test_metadata_v11(self):
        metadata_decoder = MetadataDecoder(ScaleBytes(metadata_v11_hex))
        metadata_decoder.decode()
        self.assertEqual(metadata_decoder.version.value, "MetadataV11Decoder")

        for module in metadata_decoder.metadata.modules:
            if module.calls:
                for call in module.calls:
                    for arg in call.args:
                        decoder_class = ScaleDecoder.get_decoder_class(arg.type)
                        self.assertIsNotNone(decoder_class, msg='{} is not supported by metadata'.format(arg.type))

    def test_metadata_v12(self):
        metadata_decoder = MetadataDecoder(ScaleBytes(metadata_v12_hex))
        metadata_decoder.decode()
        self.assertEqual(metadata_decoder.version.value, "MetadataV12Decoder")

        for module in metadata_decoder.metadata.modules:
            if module.calls:
                for call in module.calls:
                    for arg in call.args:
                        decoder_class = ScaleDecoder.get_decoder_class(arg.type)
                        self.assertIsNotNone(decoder_class, msg='{} is not supported by metadata'.format(arg.type))
