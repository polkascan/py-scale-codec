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
#
#  test_runtime_configuration.py
#

import unittest

from scalecodec.base import RuntimeConfiguration, RuntimeConfigurationObject
from scalecodec.type_registry import load_type_registry_preset


class TestScaleDecoderClasses(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        RuntimeConfiguration().clear_type_registry()
        RuntimeConfiguration().update_type_registry(load_type_registry_preset("default"))

    def test_valid_decoding_classes(self):
        for type_string in RuntimeConfiguration().type_registry['types'].keys():

            decoding_cls = RuntimeConfiguration().get_decoder_class(type_string)

            self.assertIsNotNone(decoding_cls, msg='"{}" didn\'t return decoding class'.format(type_string))

            # Try to decode type mapping if present
            if decoding_cls.type_mapping:
                for name, sub_type_string in decoding_cls.type_mapping:
                    sub_decoding_cls = RuntimeConfiguration().get_decoder_class(sub_type_string)

                    self.assertIsNotNone(sub_decoding_cls,
                                         msg=f' Sub type "{sub_type_string}" didn\'t return decoding class')

                    # Try to decode sub_type if present
                    if sub_decoding_cls.sub_type:
                        sub_decoding_cls = RuntimeConfiguration().get_decoder_class(sub_decoding_cls.sub_type)
                        self.assertIsNotNone(sub_decoding_cls,
                                             msg=f' Sub type "{decoding_cls.sub_type}" didn\'t return decoding class')


class TestMultipleRuntimeConfigurations(unittest.TestCase):

    def test_use_config_singleton(self):
        RuntimeConfiguration(config_id='test').update_type_registry({
            'types': {
                'CustomTestType': 'u8'
            }
        })
        self.assertIsNone(RuntimeConfiguration().get_decoder_class('CustomTestType'))
        self.assertIsNotNone(RuntimeConfiguration(config_id='test').get_decoder_class('CustomTestType'))

    def test_multiple_instances(self):
        runtime_config1 = RuntimeConfigurationObject()
        runtime_config1.update_type_registry({
            'types': {
                'MyNewType': 'Vec<u8>'
            }
        })

        runtime_config2 = RuntimeConfigurationObject()

        self.assertIsNone(RuntimeConfiguration().get_decoder_class('MyNewType'))
        self.assertIsNotNone(runtime_config1.get_decoder_class('MyNewType'))
        self.assertIsNone(runtime_config2.get_decoder_class('MyNewType'))


if __name__ == '__main__':
    unittest.main()
