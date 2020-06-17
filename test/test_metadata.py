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

import unittest

from scalecodec.base import ScaleBytes, RuntimeConfiguration, ScaleDecoder
from scalecodec.metadata import MetadataDecoder
from scalecodec.type_registry import load_type_registry_preset
from test.fixtures import metadata_v3_hex, metadata_v2_hex, metadata_v1_hex


class TestMetadata(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
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
        metadata_decoder = MetadataDecoder(ScaleBytes(metadata_v1_hex))
        self.assertRaises(Exception, metadata_decoder.decode())

    def test_all_scale_type_supported_v1(self):
        metadata_decoder = MetadataDecoder(ScaleBytes(metadata_v1_hex))
        metadata_decoder.decode()
        self.assertEqual(metadata_decoder.version.value, "MetadataV1Decoder")

        for module in metadata_decoder.metadata.modules:
            if module.calls:
                for call in module.calls:
                    for arg in call.args:
                        decoder_class = ScaleDecoder.get_decoder_class(arg.type, ScaleBytes('0x00'))
                        self.assertIsNotNone(decoder_class, msg='{} is not supported by metadata'.format(arg.type))

    def test_all_scale_type_supported_v2(self):
        metadata_decoder = MetadataDecoder(ScaleBytes(metadata_v2_hex))
        metadata_decoder.decode()
        self.assertEqual(metadata_decoder.version.value, "MetadataV2Decoder")

        for module in metadata_decoder.metadata.modules:
            if module.calls:
                for call in module.calls:
                    for arg in call.args:
                        decoder_class = ScaleDecoder.get_decoder_class(arg.type, ScaleBytes('0x00'))
                        self.assertIsNotNone(decoder_class, msg='{} is not supported by metadata'.format(arg.type))

    def test_all_scale_type_supported_v3(self):
        metadata_decoder = MetadataDecoder(ScaleBytes(metadata_v3_hex))
        metadata_decoder.decode()
        self.assertEqual(metadata_decoder.version.value, "MetadataV3Decoder")

        for module in metadata_decoder.metadata.modules:
            if module.calls:
                for call in module.calls:
                    for arg in call.args:
                        decoder_class = ScaleDecoder.get_decoder_class(arg.type, ScaleBytes('0x00'))
                        self.assertIsNotNone(decoder_class, msg='{} is not supported by metadata'.format(arg.type))


