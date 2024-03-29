#  Polkascan API extension for Substrate Interface Library
#
#  Copyright 2018-2023 Stichting Polkascan (Polkascan Foundation).
#
#  Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at
#
#  http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.
#

#  Polkascan API extension for Substrate Interface Library
#
#
#  Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at
#
#  http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.
#

import json
import re

def convert_generic_type(value):
    # Recursive function to convert generic types
    if value:
        match = re.match(r'([a-zA-Z]+)<(.+)>', value)
        if match:
            gen_type = match.group(1)
            inner_type = match.group(2)
            return f"{gen_type}({convert_generic_type(inner_type)})"
    return value

def convert_json_to_python(json_file, output_file):
    with open(json_file, 'r') as file:
        data = json.load(file)

    python_lines = []

    for key, value in data['types'].items():
        if isinstance(value, str):
            if value.startswith('[') and value.endswith(']'):
                # Array type conversion
                array_type, array_size = value[1:-1].split('; ')
                python_lines.append(f"{key} = Array({array_type}, {array_size})")
            elif '<' in value and '>' in value:
                # Generic type conversion (including nested types)
                converted_value = convert_generic_type(value)
                python_lines.append(f"{key} = {converted_value}")
            else:
                # Simple type conversion
                python_lines.append(f"{key} = {value}")
        elif isinstance(value, dict):
            if value.get('type') == 'struct':
                # Struct conversion
                struct_fields = ', '.join(f"{k}={'None' if v == 'Null' else convert_generic_type(v)}" for k, v in value['type_mapping'])
                python_lines.append(f"{key} = Struct({struct_fields})")
            elif value.get('type') == 'enum':
                if 'type_mapping' in value:
                    # Enum conversion with type mapping
                    enum_fields = ', '.join(f"{k}={'None' if v == 'Null' else convert_generic_type(v)}" for k, v in value['type_mapping'])
                elif 'value_list' in value:
                    # Enum conversion with value list
                    enum_fields = ', '.join(f"{item}=None" for item in value['value_list'])
                python_lines.append(f"{key} = Enum({enum_fields})")

    with open(output_file, 'w') as file:
        file.write('\n'.join(python_lines))


if __name__ == '__main__':
    convert_json_to_python('core.json', 'types.py')
