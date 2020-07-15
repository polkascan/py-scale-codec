#  Python SCALE Codec Library
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
#  test_runtime_configuration.py
#

import unittest

from scalecodec.base import RuntimeConfiguration
from scalecodec.type_registry import load_type_registry_preset


class TestScaleDecoderClasses(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        RuntimeConfiguration().clear_type_registry()
        RuntimeConfiguration().update_type_registry(load_type_registry_preset("default"))

    def test_valid_decoding_classes(self):
        for type_string in RuntimeConfiguration().type_registry['types'].keys():
            self.assertIsNotNone(RuntimeConfiguration().get_decoder_class(
                type_string), msg='"{}" didn\'t return decoding class'.format(type_string)
            )


if __name__ == '__main__':
    unittest.main()
