# Python SCALE Codec Library
#
# Copyright 2018-2024 Stichting Polkascan (Polkascan Foundation).
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

import unittest

from scalecodec.types import Enum, Bool, U32


class TestEnum(unittest.TestCase):

    def test_enum(self):
        scale_obj = Enum(Bool=Bool(), Number=U32, None_=None).new()
        value = {'Bool': True}

        data = scale_obj.encode(value)
        scale_obj.decode(data)

        self.assertEqual(value, scale_obj.value)

        value = {'Number': 7643}

        data = scale_obj.encode(value)
        scale_obj.decode(data)

        self.assertEqual(value, scale_obj.value)

        value = 'None'

        data = scale_obj.encode(value)
        scale_obj.decode(data)

        self.assertEqual(value, scale_obj.value)


if __name__ == '__main__':
    unittest.main()
