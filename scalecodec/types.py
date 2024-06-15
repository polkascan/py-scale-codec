# Python SCALE Codec Library
#
# Copyright 2018-2023 Stichting Polkascan (Polkascan Foundation).
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

import math
from hashlib import blake2b
from typing import Union, Optional, List, Type

from scalecodec.base import ScaleType, ScaleBytes, ScalePrimitive, ScaleTypeDef, RegistryTypeDef
from scalecodec.constants import TYPE_DECOMP_MAX_RECURSIVE, DEFAULT_EXTRINSIC_VERSION, BIT_SIGNED, BIT_UNSIGNED, \
    UNMASK_VERSION
from scalecodec.exceptions import InvalidScaleTypeValueException, ScaleEncodeException, ScaleDecodeException
from scalecodec.migrations.runtime_calls import get_apis, get_type_def
from scalecodec.utils.math import trailing_zeros, next_power_of_two
from scalecodec.utils.ss58 import ss58_encode, ss58_decode_account_index, is_valid_ss58_address, ss58_decode


class UnsignedInteger(ScalePrimitive):
    """
    Unsigned int type, encoded in little-endian (LE) format
    """

    def __init__(self, bits: int):
        super().__init__()
        self.bits = bits
        self.byte_count = int(self.bits / 8)

    def decode(self, data: ScaleBytes) -> int:
        return int.from_bytes(data.get_next_bytes(self.byte_count), byteorder='little')

    def process_encode(self, value) -> ScaleBytes:

        if 0 <= int(value) <= 2**(self.byte_count * 8) - 1:
            return ScaleBytes(bytearray(int(value).to_bytes(self.byte_count, 'little')))
        else:
            raise ScaleEncodeException(f'{value} out of range for u{self.bits}')

    def serialize(self, value: int) -> int:
        return value

    def deserialize(self, value: int) -> int:
        if type(value) is not int:
            raise ValueError('Value must be an integer')
        return value

    def example_value(self, _recursion_level: int = 0, max_recursion: int = TYPE_DECOMP_MAX_RECURSIVE):
        return self.bits


class SignedInteger(ScalePrimitive):
    """
    Signed int type, encoded in little-endian (LE) format
    """

    def __init__(self, bits: int):
        super().__init__()
        self.bits = bits
        self.byte_count = int(self.bits / 8)

    def decode(self, data: ScaleBytes) -> int:
        return int.from_bytes(data.get_next_bytes(self.byte_count), byteorder='little', signed=True)

    def process_encode(self, value) -> ScaleBytes:

        if -2**self.bits <= int(value) <= 2**self.bits - 1:
            return ScaleBytes(bytearray(int(value).to_bytes(self.byte_count, 'little', signed=True)))
        else:
            raise ScaleEncodeException(f'{value} out of range for i{self.bits}')

    def serialize(self, value: int) -> int:
        return value

    def deserialize(self, value: int) -> int:
        if type(value) is not int:
            raise ValueError('Value must be an integer')
        return value

    def example_value(self, _recursion_level: int = 0, max_recursion: int = TYPE_DECOMP_MAX_RECURSIVE):
        return -self.bits


U8 = UnsignedInteger(8)
U16 = UnsignedInteger(16)
U32 = UnsignedInteger(32)
U64 = UnsignedInteger(64)
U128 = UnsignedInteger(128)
U256 = UnsignedInteger(256)

I8 = SignedInteger(8)
I16 = SignedInteger(16)
I32 = SignedInteger(32)
I64 = SignedInteger(64)
I128 = SignedInteger(128)
I256 = SignedInteger(256)


class Bool(ScalePrimitive):

    @classmethod
    def new(cls):
        return ScaleType(type_def=cls())

    def decode(self, data: ScaleBytes) -> bool:

        bool_data = data.get_next_bytes(1)
        if bool_data not in [b'\x00', b'\x01']:
            raise ScaleDecodeException('Invalid value for datatype "bool"')
        return bool_data == b'\x01'

    def process_encode(self, value: bool) -> ScaleBytes:
        if value is True:
            return ScaleBytes('0x01')
        elif value is False:
            return ScaleBytes('0x00')
        else:
            raise ScaleEncodeException("Value must be boolean")

    def serialize(self, value: bool) -> bool:
        return value

    def deserialize(self, value: bool) -> bool:
        return value

    def example_value(self, _recursion_level: int = 0, max_recursion: int = TYPE_DECOMP_MAX_RECURSIVE):
        return True

class NullType(ScaleTypeDef):

    def decode(self, data: ScaleBytes) -> any:
        return None

    def process_encode(self, value: any) -> ScaleBytes:
        return ScaleBytes(bytearray())

    def serialize(self, value: any) -> any:
        return None

    def deserialize(self, value: any) -> any:
        return None

    def example_value(self, _recursion_level: int = 0, max_recursion: int = TYPE_DECOMP_MAX_RECURSIVE):
        return None


Null = NullType()


class Struct(ScaleTypeDef):

    arguments = None

    def __init__(self, **kwargs):
        if len(kwargs) > 0:
            self.arguments = {key.rstrip('_'): value for key, value in kwargs.items()}
        super().__init__()

    def process_encode(self, value):
        data = ScaleBytes(bytearray())
        for name, scale_obj in self.arguments.items():

            if name not in value:
                raise ScaleEncodeException(f'Argument "{name}" of Struct is missing in given value')

            # if scale_obj.scale_type_cls is value[name].__class__:
            #     # Todo make generic
            #     data += value[name].data
            # else:
            data += scale_obj.new().encode(value[name])

            if value[name] and issubclass(value[name].__class__, ScaleType):
                value[name] = value[name].serialize()

        return data

    def decode(self, data) -> dict:
        value = {}

        for key, scale_def in self.arguments.items():

            scale_obj = scale_def.new()
            scale_obj.decode(data)

            value[key] = scale_obj

        return value

    def serialize(self, value: dict) -> dict:
        return {k: obj.value for k, obj in value.items()}

    def deserialize(self, value: dict) -> dict:
        value_object = {}

        for key, scale_def in self.arguments.items():
            if key in value:
                scale_obj = scale_def.new()

                scale_obj.value_serialized = value[key]
                scale_obj.deserialize(value[key])

                value_object[key] = scale_obj

        return value_object

    def example_value(self, _recursion_level: int = 0, max_recursion: int = TYPE_DECOMP_MAX_RECURSIVE):

        if _recursion_level > max_recursion:
            return f'<{self.__class__.__name__}>'

        return {
            k: scale_def.example_value(_recursion_level + 1, max_recursion) for k, scale_def in self.arguments.items()
        }


class Tuple(ScaleTypeDef):

    values = None

    def __init__(self, *args, **kwargs):
        if len(args) > 0:
            self.values = args
        super().__init__()

    def process_encode(self, value: tuple) -> ScaleBytes:
        if type(value) is not tuple:
            value = [value]

        data = ScaleBytes(bytearray())
        for idx, scale_obj in enumerate(self.values):

            data += scale_obj.new().encode(value[idx])
        return data

    def decode(self, data: ScaleBytes) -> tuple:
        value = ()

        for scale_def in self.values:
            scale_obj = scale_def.new()

            scale_obj.decode(data)
            value += (scale_obj,)

        return value

    def serialize(self, value: tuple) -> tuple:
        if len(value) == 1:
            return value[0].value

        return tuple((i.value for i in value))

    def deserialize(self, value: tuple) -> tuple:
        value_object = ()

        for idx, scale_def in enumerate(self.values):
            scale_obj = scale_def.new()

            scale_obj.value_serialized = value
            scale_obj.deserialize(value[idx])
            value_object += (scale_obj,)

        return value_object

    def example_value(self, _recursion_level: int = 0, max_recursion: int = TYPE_DECOMP_MAX_RECURSIVE):
        return tuple([i.example_value() for i in self.values])

class EnumType(ScaleType):

    @property
    def index(self):
        if self.value_object is not None:
            for index, name in enumerate(self.type_def.variants.keys()):
                if name == self.value_object[0]:
                    return index


class Enum(ScaleTypeDef):

    variants = None

    def __init__(self, **kwargs):
        super().__init__()

        if len(kwargs) > 0:
            self.variants = {key.rstrip('_'): value for key, value in kwargs.items()}

        if self.scale_type_cls is None:
            self.scale_type_cls = EnumType

    def process_encode(self, value: Union[str, dict]) -> ScaleBytes:

        # if issubclass(value.__class__, ScaleType) and value.type_def.__class__ is self.__class__:
        #     value = value.value

        if type(value) is dict:
            value = value.copy()

        if type(value) is str:
            # Convert simple enum values
            value = {value: None}

        if type(value) is not dict:
            raise ScaleEncodeException(f"Value must be a dict or str when encoding enums, not '{value}'")

        if len(value) != 1:
            raise ScaleEncodeException("Only one variant can be specified for enums")

        enum_key, enum_value = list(value.items())[0]

        for idx, (variant_name, variant_obj) in enumerate(self.variants.items()):

            if enum_key == variant_name:

                data = ScaleBytes(bytearray([idx]))

                if variant_obj is not None:

                    data += variant_obj.new().encode(enum_value)

                return data

        raise ScaleEncodeException(f"Variant '{enum_key}' not defined for this enum")

    def decode(self, data: ScaleBytes) -> tuple:

        index = int.from_bytes(data.get_next_bytes(1), byteorder='little')

        try:
            enum_key, enum_variant = list(self.variants.items())[index]
        except IndexError:
            raise ScaleDecodeException(f"Index '{index}' not present in Enum type mapping")

        if enum_variant is None:
            return (enum_key, None)
        else:
            scale_obj = enum_variant.new()
            scale_obj.decode(data)
            return (enum_key, scale_obj)

    def serialize(self, value: tuple) -> Union[str, dict]:
        if value[1] is None:
            return value[0]
        else:
            return {value[0]: value[1].value}

    def deserialize(self, value: Union[str, dict]) -> tuple:
        if type(value) is str:
            value = {value: None}

        enum_key, enum_value = list(value.items())[0]

        for idx, (variant_name, variant_obj) in enumerate(self.variants.items()):

            if enum_key == variant_name:

                if variant_obj is not None:
                    enum_value_obj = variant_obj.new()
                    enum_value_obj.value_serialized = enum_value
                    enum_value_obj.deserialize(enum_value)
                else:
                    enum_value_obj = None

                return (enum_key, enum_value_obj)

        raise ValueError(f"Error while deserializing Enum; variant '{enum_key}' not found")

    def example_value(self, _recursion_level: int = 0, max_recursion: int = TYPE_DECOMP_MAX_RECURSIVE):

        if _recursion_level > max_recursion:
            return f'<{self.__class__.__name__}>'

        example = {}
        for idx, (variant_name, variant_obj) in enumerate(self.variants.items()):
            if not variant_name.startswith('__'):
                if variant_obj is None:
                    example[variant_name] = None
                else:
                    example[variant_name] = variant_obj.example_value(_recursion_level + 1, max_recursion)
        return example


class Option(ScaleTypeDef):
    def __init__(self, some):
        self.some = some
        super().__init__()

    def process_encode(self, value: any) -> ScaleBytes:
        if value is None:
            return ScaleBytes('0x00')
        else:
            return ScaleBytes('0x01') + self.some.encode(value, external_call=False)

    def decode(self, data: ScaleBytes) -> Optional[ScaleType]:
        if data.get_next_bytes(1) == b'\x00':
            return None
        else:
            scale_obj = self.some.new()
            scale_obj.decode(data)
            return scale_obj

    def serialize(self, value: Optional[ScaleType]) -> any:
        if value is not None:
            return value.value

    def deserialize(self, value: any) -> Optional[ScaleType]:
        if value is not None:
            some_obj = self.some.new()
            some_obj.deserialize(value)
            return some_obj

    def example_value(self, _recursion_level: int = 0, max_recursion: int = TYPE_DECOMP_MAX_RECURSIVE):
        return None, self.some.example_value()


class Compact(ScaleTypeDef):
    def __init__(self, type_: ScaleTypeDef = None):
        self.type = type_
        self.compact_length = 0
        self.compact_bytes = None
        super().__init__()

    def process_compact_bytes(self, data):
        compact_byte = data.get_next_bytes(1)
        try:
            byte_mod = compact_byte[0] % 4
        except IndexError:
            raise ScaleDecodeException("Invalid byte for Compact")

        if byte_mod == 0:
            self.compact_length = 1
        elif byte_mod == 1:
            self.compact_length = 2
        elif byte_mod == 2:
            self.compact_length = 4
        else:
            self.compact_length = int(5 + (compact_byte[0] - 3) / 4)

        if self.compact_length == 1:
            self.compact_bytes = compact_byte
        elif self.compact_length in [2, 4]:
            self.compact_bytes = compact_byte + data.get_next_bytes(self.compact_length - 1)
        else:
            self.compact_bytes = data.get_next_bytes(self.compact_length - 1)

        return self.compact_bytes

    def decode(self, data: ScaleBytes) -> any:
        self.process_compact_bytes(data)

        if self.compact_length <= 4:
            return int(int.from_bytes(self.compact_bytes, byteorder='little') / 4)
        else:
            return int.from_bytes(self.compact_bytes, byteorder='little')

    def process_encode(self, value: int) -> ScaleBytes:

        value = int(value)

        if value <= 0b00111111:
            return ScaleBytes(bytearray(int(value << 2).to_bytes(1, 'little')))

        elif value <= 0b0011111111111111:
            return ScaleBytes(bytearray(int((value << 2) | 0b01).to_bytes(2, 'little')))

        elif value <= 0b00111111111111111111111111111111:
            return ScaleBytes(bytearray(int((value << 2) | 0b10).to_bytes(4, 'little')))

        else:
            for bytes_length in range(4, 68):
                if 2 ** (8 * (bytes_length - 1)) <= value < 2 ** (8 * bytes_length):
                    return ScaleBytes(bytearray(
                        ((bytes_length - 4) << 2 | 0b11).to_bytes(1, 'little') + value.to_bytes(bytes_length,
                                                                                                'little')))
            else:
                raise ScaleEncodeException('{} out of range'.format(value))

    def example_value(self, _recursion_level: int = 0, max_recursion: int = TYPE_DECOMP_MAX_RECURSIVE):
        return 1

    def serialize(self, value: int) -> int:
        return value

    def deserialize(self, value: int) -> int:
        if type(value) is not int:
            raise ValueError('Value must be an integer')
        return value


class VecType(ScaleType):

    def __len__(self):
        return len(self.value_object)


class Vec(ScaleTypeDef):
    def __init__(self, type_def: ScaleTypeDef):
        super().__init__()
        self.scale_type_cls = VecType
        self.type_def = type_def

    def process_encode(self, value: list) -> ScaleBytes:

        if self.type_def is U8:
            return Bytes.encode(value, external_call=False)

        # Encode length of Vec
        data = Compact().new().encode(len(value))

        for idx, item in enumerate(value):
            data += self.type_def.new().encode(item)
            if item and issubclass(item.__class__, ScaleType):
                value[idx] = item.serialize()

        return data

    def decode(self, data: ScaleBytes) -> list:

        if self.type_def is U8:
            return Bytes.decode(data)

        # Decode length of Vec
        length = Compact().decode(data)

        value = []

        for _ in range(0, length):
            obj = self.type_def.new()
            obj.decode(data)

            value.append(obj)

        return value

    def serialize(self, value: list) -> list:
        if self.type_def is U8:
            return Bytes.serialize(value)
        return [i.value_serialized for i in value]

    def deserialize(self, value: list) -> list:
        if self.type_def is U8:
            return Bytes.deserialize(value)


        value_object = []

        for item in value:
            obj = self.type_def.new()
            obj.value_serialized = item
            obj.deserialize(item)

            value_object.append(obj)

        return value_object

    def example_value(self, _recursion_level: int = 0, max_recursion: int = TYPE_DECOMP_MAX_RECURSIVE):
        if self.type_def is U8:
            return b'Bytes'
        return [self.type_def.example_value()]


class BitVec(ScaleTypeDef):
    """
    A BitVec that represents an array of bits. The bits are however stored encoded. The difference between this
    and a normal Bytes would be that the length prefix indicates the number of bits encoded, not the bytes
    """

    def process_encode(self, value: Union[list, str, int]) -> ScaleBytes:

        if type(value) is list:
            value = sum(v << i for i, v in enumerate(reversed(value)))

        if type(value) is str and value[0:2] == '0b':
            value = int(value[2:], 2)

        if type(value) is not int:
            raise ScaleEncodeException("Provided value is not an int, binary str or a list of booleans")

        if value == 0:
            return ScaleBytes(b'\x00')

        # encode the length in a compact u32
        data = Compact().encode(value.bit_length(), external_call=False)

        byte_length = math.ceil(value.bit_length() / 8)

        return data + value.to_bytes(length=byte_length, byteorder='little')

    def decode(self, data: ScaleBytes) -> str:
        # Decode length of Vec
        length = Compact().decode(data)

        total = math.ceil(length / 8)

        value_int = int.from_bytes(data.get_next_bytes(total), byteorder='little')

        return '0b' + bin(value_int)[2:].zfill(length)

    def serialize(self, value: str) -> str:
        return value

    def deserialize(self, value: str) -> str:
        return value


class Array(ScaleTypeDef):
    def __init__(self, type_def: ScaleTypeDef, length: int):
        self.type_def = type_def
        self.length = length
        super().__init__()

    def process_encode(self, value: Union[list, str, bytes]) -> ScaleBytes:

        if self.type_def is U8:

            if type(value) is list:
                value = bytes(value)
            elif type(value) is str:
                if value[0:2] == '0x':
                    value = bytes.fromhex(value[2:])
                else:
                    value = value.encode('utf-8')

            if type(value) is not bytes:
                raise ScaleEncodeException('value should be of type list, str or bytes')

            if len(value) != self.length:
                raise ScaleEncodeException(f'Value should be {self.length} bytes long')

            return ScaleBytes(value)
        else:
            data = ScaleBytes(bytearray())

            if type(value) is not list:
                raise ScaleEncodeException("Value must be of type list")

            if len(value) != self.length:
                raise ScaleEncodeException("Length of list does not match size of array")

            for item in value:
                data += self.type_def.encode(item)

            return data

    def decode(self, data: ScaleBytes) -> Union[list, bytes]:
        if self.type_def is U8:
            return data.get_next_bytes(self.length)
        else:
            value = []

            for _ in range(0, self.length):
                obj = self.type_def.new()
                obj.decode(data)

                value.append(obj)

            return value

    def serialize(self, value: Union[list, bytes]) -> Union[list, str]:
        if type(value) is list:
            return [i.value_serialized for i in value]
        else:
            return f'0x{value.hex()}'

    def deserialize(self, value: Union[list, str, bytes]) -> Union[list, bytes]:
        if type(value) is str:
            if value[0:2] == '0x':
                return bytes.fromhex(value[2:])
            else:
                return value.encode()
        else:
            value_object = []

            for item in value:
                obj = self.type_def.new()
                obj.value_serialized = item
                obj.deserialize(item)

                value_object.append(obj)

            return value_object

    def example_value(self, _recursion_level: int = 0, max_recursion: int = TYPE_DECOMP_MAX_RECURSIVE):
        if self.type_def is U8:
            return f'0x{str(self.length).zfill(2) * self.length}'
        else:
            return [self.type_def.example_value()] * self.length


class DataType(EnumType):

    def decode(self, data: ScaleBytes, check_remaining=False) -> any:
        value = super().decode(data)

        if type(value) is dict:
            items = list(value.items())[0]
            if items[0].startswith('Raw'):
                self.value_serialized = {'Raw': items[1]}
                self.value_object = ('Raw', self.value_object[1])

        return self.value_serialized

    def encode(self, value: dict) -> ScaleBytes:
        items = list(value.items())[0]
        if items[0] == 'Raw':
            value = {f'Raw{len(items[1])}': items[1]}

        return super().encode(value)


class Map(ScaleTypeDef):
    def __init__(self, key_def: ScaleTypeDef, value_def: ScaleTypeDef):
        super().__init__()
        # self.scale_type_cls = VecType
        self.key_def = key_def
        self.value_def = value_def

    def process_encode(self, value: list) -> ScaleBytes:
        # Encode length of Vec
        data = Compact().encode(len(value))

        for item_key, item_value in value:
            data += self.key_def.encode(item_key)
            data += self.value_def.encode(item_value)

        return data

    def decode(self, data: ScaleBytes) -> list:
        # Decode length of Map
        length = Compact().decode(data)

        value = []

        for _ in range(0, length):
            key_obj = self.key_def.new()
            key_obj.decode(data)
            value_obj = self.value_def.new()
            value_obj.decode(data)
            value.append((key_obj, value_obj))

        return value

    def serialize(self, value: list) -> list:
        return [(k.value_serialized, v.value_serialized) for k, v in value]


class Bytes(ScaleTypeDef):
    """
    A variable collection of bytes, stored as an `Vec<u8>`
    """

    def process_encode(self, value: Union[str, bytes, bytearray, list]) -> ScaleBytes:

        if type(value) is str:
            if value[0:2] == '0x':
                # TODO implicit HexBytes conversion can have unexpected result if string is actually starting with '0x'
                value = bytes.fromhex(value[2:])
            else:
                value = value.encode('utf-8')

        elif type(value) in (bytearray, list):
            value = bytes(value)

        if type(value) is not bytes:
            raise ScaleEncodeException(f'Cannot encode type "{type(value)}"')

        # Encode length of Vec
        data = Compact().new().encode(len(value))

        return data + value

    def decode(self, data: ScaleBytes) -> bytearray:
        # Decode length of Vec
        length = Compact().decode(data)

        return data.get_next_bytes(length)

    def serialize(self, value: bytearray) -> str:
        return f'0x{value.hex()}'

    def deserialize(self, value: str) -> bytearray:
        if type(value) is str:
            if value[0:2] == '0x':
                value = bytearray.fromhex(value[2:])
            else:
                value = value.encode('utf-8')
        return value

    def example_value(self, _recursion_level: int = 0, max_recursion: int = TYPE_DECOMP_MAX_RECURSIVE):
        return b'Bytes'


class String(Bytes):
    def decode(self, data: ScaleBytes) -> str:
        value = super().decode(data)

        try:
            return value.decode()
        except UnicodeDecodeError:
            return '0x{}'.format(value.hex())

    def serialize(self, value: str) -> str:
        return value

    def deserialize(self, value: str) -> str:
        return value


    def create_example(self, _recursion_level: int = 0):
        return 'String'

class HashDef(ScaleTypeDef):

    def __init__(self, bits: int):
        super().__init__()
        self.bits = bits
        self.byte_count = int(self.bits / 8)

    def decode(self, data: ScaleBytes) -> bytes:
        return data.get_next_bytes(self.byte_count)

    def process_encode(self, value: Union[str, bytes]) -> ScaleBytes:

        if type(value) is str:
            if value[0:2] != '0x' or len(value) != (self.byte_count*2)+2:
                raise ScaleEncodeException(f'Value should start with "0x" and should be {self.byte_count} bytes long')

            value = bytes.fromhex(value[2:])

        if type(value) is not bytes:
            raise ScaleEncodeException('value should be of type str or bytes')

        if len(value) != self.byte_count:
            raise ScaleEncodeException(f'Value should be {self.byte_count} bytes long')

        return ScaleBytes(value)

    def serialize(self, value: bytes) -> str:
        return f'0x{value.hex()}'

    def deserialize(self, value: str) -> bytes:
        return bytes.fromhex(value[2:])

    def example_value(self, _recursion_level: int = 0, max_recursion: int = TYPE_DECOMP_MAX_RECURSIVE):
        return f'0x{str(self.byte_count).zfill(2) * self.byte_count}'


class TypeNotSupported(ScaleTypeDef):

    def __init__(self, type_string):
        self.type_string = type_string
        super().__init__()

    def new(self):
        raise NotImplementedError(f"Type {self.type_string} not supported")

    def process_encode(self, value: any) -> ScaleBytes:
        raise NotImplementedError(f"Type {self.type_string} not supported")

    def decode(self, data: ScaleBytes) -> any:
        raise NotImplementedError(f"Type {self.type_string} not supported")


class GenericRegistryType(ScaleType):

    @property
    def docs(self):
        return self.value['docs']

    def encode(self, value):
        if 'params' not in value:
            value['params'] = []

        if 'path' not in value:
            value['path'] = []

        if 'docs' not in value:
            value['docs'] = []

        return super().encode(value)


class GenericPortableRegistry(ScaleType):

    def __init__(self, type_def: ScaleTypeDef, runtime_config=None):
        super().__init__(type_def)
        self.runtime_config = runtime_config
        self.si_type_registry = {}
        self.path_lookup = {}

        self.__def_overrides = {
            "sp_core::crypto::AccountId32": AccountId(),
            'sp_runtime::multiaddress::MultiAddress': MultiAddress(),
            'sp_runtime::generic::era::Era': Era(),
            'frame_system::extensions::check_mortality::CheckMortality': Era(),
        }

        self.__impl_overrides = {
            'RuntimeCall': GenericCall,
            # 'Call': GenericCall,
            'EventRecord': GenericEventRecord,
            'pallet_identity::types::Data': DataType
        }

        self.__primitive_types = {
            'U8': U8,
            'u8': U8,
            'u16': U16,
            'u32': U32,
            'u64': U64,
            'u128': U128,
            'u256': U256,
            'i8': I8,
            'i16': I16,
            'i32': I32,
            'i64': I64,
            'i128': I128,
            'i256': I256,
            'bool': Bool(),
            'str': String
        }

    def get_registry_type(self, si_type_id: int) -> GenericRegistryType:
        try:
            return self.value_object['types'][si_type_id]['type']
        except IndexError:
            raise ValueError(f"RegistryType not found with id {si_type_id}")

    def get_primitive_type_def(self, type_string: str) -> ScaleTypeDef:
        if type_string not in self.__primitive_types:
            raise ValueError(f"{type_string} is not a valid primitive")
        return self.__primitive_types[type_string]

    def get_scale_type_def(self, si_type_id: int) -> ScaleTypeDef:
        if si_type_id not in self.si_type_registry:
            # Create placeholder to prevent recursion issues
            self.si_type_registry[si_type_id] = RegistryTypeDef(self, si_type_id)
            self.si_type_registry[si_type_id] = self.create_scale_type_def(si_type_id)

        return self.si_type_registry[si_type_id]

    def get_si_type_id(self, path: str) -> int:
        if not self.path_lookup:
            self.path_lookup = {'::'.join(t['type']['path']).lower(): t['id'] for t in self.value_object['types'].value if t['type']['path']}
        si_type_id = self.path_lookup.get(path.lower())

        if si_type_id is None:
            raise ValueError(f"Path '{path}' is not found in portable registry")

        return si_type_id

    def get_type_def_primitive(self, name) -> ScaleTypeDef:
        type_def = self.__primitive_types.get(name.lower())

        if type_def is None:
            raise ValueError(f"Primitive '{name}' not found ")

        return type_def

    def get_type_def_override_for_path(self, path: list) -> Optional[ScaleTypeDef]:
        type_def = self.__def_overrides.get(path[-1])
        if type_def is None:
            type_def = self.__def_overrides.get('::'.join(path))
        return type_def

    def get_impl_override_for_path(self, path: list) -> Optional[Type[ScaleType]]:
        scale_type_cls = self.__impl_overrides.get(path[-1])
        if scale_type_cls is None:
            scale_type_cls = self.__impl_overrides.get('::'.join(path))
        return scale_type_cls

    def create_scale_type_def(self, si_type_id: int) -> ScaleTypeDef:

        registry_type = self.value_object['types'][si_type_id]['type']

        # Check if def override is defined for path
        type_impl_override = None

        if 'path' in registry_type.value and len(registry_type.value['path']) > 0:
            type_def_override = self.get_type_def_override_for_path(registry_type.value['path'])
            if type_def_override:
                return type_def_override

            type_impl_override = self.get_impl_override_for_path(registry_type.value['path'])

        if "primitive" in registry_type.value["def"]:
            try:
                return self.__primitive_types[registry_type.value["def"]["primitive"]]
            except KeyError:
                raise ValueError(f'Primitive type "{registry_type.value["def"]["primitive"]}" not found')

        elif 'array' in registry_type.value["def"]:

            return Array(
                self.get_scale_type_def(registry_type.value['def']['array']['type']),
                registry_type.value['def']['array']['len']
            )

        elif 'composite' in registry_type.value["def"]:

            fields = registry_type.value["def"]['composite']['fields']

            if all([f.get('name') for f in fields]):

                fields = {field['name']: self.get_scale_type_def(field['type']) for field in fields}
                type_def = Struct(**fields)

            else:
                items = [self.get_scale_type_def(field['type']) for field in fields]
                type_def = Tuple(*items)

            if type_impl_override:
                type_def = type_def.impl(type_impl_override)

            return type_def

        elif 'sequence' in registry_type.value["def"]:
            # Vec
            type_def = self.get_scale_type_def(registry_type.value['def']['sequence']['type'])
            return Vec(type_def)

        elif 'variant' in registry_type.value["def"]:

            if registry_type.value["path"] == ['Option']:
                # Option
                return Option(self.get_scale_type_def(registry_type.value['params'][0]['type']))

            # Enum
            variants_mapping = []

            variants = registry_type.value["def"]['variant']['variants']

            if len(variants) > 0:
                # Create placeholder list
                variant_length = max([v['index'] for v in variants]) + 1
                variants_mapping = [(f'__{i}', Null) for i in range(0, variant_length)]

                for variant in variants:

                    if 'fields' in variant:
                        if len(variant['fields']) == 0:
                            enum_value = None
                        elif all([f.get('name') for f in variant['fields']]):
                            # Enum with named fields
                            fields = {f.get('name'): self.get_scale_type_def(f['type']) for f in variant['fields']}
                            enum_value = Struct(**fields)
                        else:
                            if len(variant['fields']) == 1:
                                enum_value = self.get_scale_type_def(variant['fields'][0]['type'])
                            else:
                                items = [self.get_scale_type_def(f['type']) for f in variant['fields']]
                                enum_value = Tuple(*items)
                    else:
                        enum_value = Null

                    # Put mapping in right order in list
                    variants_mapping[variant['index']] = (variant['name'], enum_value)

            # TODO convert reserved names
            variants_dict = {v[0]: v[1] for v in variants_mapping}
            type_def = Enum(**variants_dict)

            if type_impl_override:
                type_def = type_def.impl(type_impl_override)

            return type_def

        elif 'tuple' in registry_type.value["def"]:

            items = [self.get_scale_type_def(i) for i in registry_type.value["def"]['tuple']]
            return Tuple(*items)

        elif 'compact' in registry_type.value["def"]:
            # Compact
            return Compact(self.get_scale_type_def(registry_type.value["def"]['compact']["type"]))

        elif 'phantom' in registry_type.value["def"]:
            return Null

        elif 'bitsequence' in registry_type.value["def"]:
            return BitVec()

        else:
            raise NotImplementedError(f"RegistryTypeDef {registry_type.value['def']} not implemented")


class GenericAccountId(ScaleType):

    def __init__(self, type_def: ScaleTypeDef, metadata: 'GenericMetadataVersioned' = None, ss58_format=None):
        self.ss58_format = ss58_format
        self.ss58_address = None
        self.public_key = None
        super().__init__(type_def, metadata)

    def encode(self, value: any) -> ScaleBytes:
        if type(value) is str:
            if value[0:2] == '0x':
                self.public_key = value
            else:
                from scalecodec.utils.ss58 import ss58_decode
                self.ss58_address = value
                self.public_key = f'0x{ss58_decode(value)}'

        return super().encode(self.public_key)

    def decode(self, data: ScaleBytes) -> any:
        value = super().decode(data)
        self.public_key = f'0x{self.value_object.hex()}'
        return value

    def serialize(self) -> str:
        if self.ss58_format is None:
            ss58_format = 42
        else:
            ss58_format = self.ss58_format

        try:
            self.ss58_address = ss58_encode(self.value_object, ss58_format=ss58_format)
            return self.ss58_address
        except ValueError:
            return super().serialize()


class AccountId(HashDef):

    def __init__(self, ss58_format=None):
        self.ss58_format = ss58_format
        super().__init__(256)

    def new(self, ss58_format=None) -> GenericAccountId:
        if ss58_format is None:
            ss58_format = self.ss58_format
        return GenericAccountId(type_def=self, ss58_format=ss58_format)

    def process_encode(self, value: any) -> ScaleBytes:
        if type(value) is str and value[0:2] != '0x':
            from scalecodec.utils.ss58 import ss58_decode
            value = f'0x{ss58_decode(value)}'

        return super().process_encode(value)

    def deserialize(self, value: str) -> bytes:
        if type(value) is str and value[0:2] != '0x':
            from scalecodec.utils.ss58 import ss58_decode
            value = f'0x{ss58_decode(value)}'

        return super().deserialize(value)

    def example_value(self, _recursion_level: int = 0, max_recursion: int = TYPE_DECOMP_MAX_RECURSIVE):
        return '5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY'


class GenericMultiAddress(ScaleType):
    pass


class MultiAddress(Enum):

    def __init__(self, ss58_format: int = None):
        self.ss58_format = ss58_format
        super().__init__(
            Id=AccountId(ss58_format=ss58_format),
            Index=Compact(),
            Raw=Bytes,
            Address32=Array(U8, 32),
            Address20=Array(U8, 20)
        )

    def new(self) -> GenericMultiAddress:
        return GenericMultiAddress(type_def=self)

    def set_ss58_format(self, ss58_format: int):
        self.ss58_format = ss58_format
        self.variants['Id'] = AccountId(ss58_format=ss58_format)

    def process_encode(self, value: Union[str, dict]) -> ScaleBytes:
        if type(value) is int:
            # Implied decoded AccountIndex
            value = {"Index": value}

        elif type(value) is str:
            if len(value) <= 8 and value[0:2] != '0x':
                # Implied raw AccountIndex
                value = {"Index": ss58_decode_account_index(value)}
            elif is_valid_ss58_address(value):
                # Implied SS58 encoded AccountId
                value = {"Id": f'0x{ss58_decode(value)}'}
            elif len(value) == 66 and value[0:2] == '0x':
                # Implied raw AccountId
                value = {"Id": value}
            elif len(value) == 42:
                # Implied raw Address20
                value = {"Address20": value}
            else:
                raise ScaleEncodeException("Address type not yet supported")

        return super().process_encode(value)

    def deserialize(self, value: Union[str, dict]) -> tuple:
        if type(value) is int:
            # Implied decoded AccountIndex
            value = {"Index": value}

        elif type(value) is str:
            if len(value) <= 8 and value[0:2] != '0x':
                # Implied raw AccountIndex
                value = {"Index": ss58_decode_account_index(value)}
            elif is_valid_ss58_address(value):
                # Implied SS58 encoded AccountId
                value = {"Id": f'0x{ss58_decode(value)}'}
            elif len(value) == 66 and value[0:2] == '0x':
                # Implied raw AccountId
                value = {"Id": value}
            elif len(value) == 42:
                # Implied raw Address20
                value = {"Address20": value}
            else:
                raise ValueError("Address type not yet supported")

        return super().deserialize(value)


class GenericCall(EnumType):
    pass


class GenericEventRecord(ScaleType):

    @property
    def extrinsic_idx(self) -> Optional[int]:
        if self.value and 'ApplyExtrinsic' in self.value['phase']:
            return self.value['phase']['ApplyExtrinsic']

    @property
    def pallet_name(self):
        return self.value_object['event'][0]

    @property
    def event_name(self):
        return self.value_object['event'][1][0]

    @property
    def attributes(self):
        return self.value_object['event'][1][1]


class ExtrinsicV4Def(Struct):

    @classmethod
    def create_from_metadata(cls, metadata: 'GenericMetadataVersioned'):
        # Process signed extensions in metadata
        signed_extensions = metadata.get_signed_extensions()

        variants = {
            'address': metadata.get_address_type_def(),
            'signature': metadata.get_extrinsic_signature_type_def()
        }

        if len(signed_extensions) > 0:

            if 'CheckMortality' in signed_extensions:
                variants['era'] = signed_extensions['CheckMortality']['extrinsic']

            if 'CheckEra' in signed_extensions:
                variants['era'] = signed_extensions['CheckEra']['extrinsic']

            if 'CheckNonce' in signed_extensions:
                variants['nonce'] = signed_extensions['CheckNonce']['extrinsic']

            if 'ChargeTransactionPayment' in signed_extensions:
                variants['tip'] = signed_extensions['ChargeTransactionPayment']['extrinsic']

            if 'ChargeAssetTxPayment' in signed_extensions:
                variants['asset_id'] = signed_extensions['ChargeAssetTxPayment']['extrinsic']

        variants['call'] = metadata.get_call_type_def()

        return cls(**variants)


class InherentDef(Struct):

    @classmethod
    def create_from_metadata(cls, metadata: 'GenericMetadataVersioned'):
        variants = {'call': metadata.get_call_type_def()}
        return cls(**variants)


class Extrinsic(Struct):

    def __init__(self, metadata: 'GenericMetadataVersioned', **kwargs):
        super().__init__(**kwargs)
        self.scale_type_cls = GenericExtrinsic
        self.metadata = metadata
        self.versions = None

    def new(self, **kwargs) -> 'ScaleType':
        # return self.scale_type_cls(type_def=self, metadata=self.metadata)
        return self.scale_type_cls(type_def=self, metadata=self.metadata, **kwargs)

    def get_signed_extrinsic_def(self, extrinsic_version: int):
        if not self.versions:
            self.versions = (
                TypeNotSupported("ExtrinsicV1"),
                TypeNotSupported("ExtrinsicV2"),
                TypeNotSupported("ExtrinsicV3"),
                ExtrinsicV4Def.create_from_metadata(metadata=self.metadata),
            )
        return self.versions[extrinsic_version - 1]

    def get_unsigned_extrinsic_def(self, extrinsic_version: int):
        return InherentDef.create_from_metadata(self.metadata)

    # TODO encode must return ScaleType object?
    def process_encode(self, value) -> ScaleBytes:

        if 'address' in value and 'signature' in value:
            data = ScaleBytes(bytes([DEFAULT_EXTRINSIC_VERSION | BIT_SIGNED]))
            extrinsic_def = self.get_signed_extrinsic_def(DEFAULT_EXTRINSIC_VERSION)
        else:
            data = ScaleBytes(bytes([DEFAULT_EXTRINSIC_VERSION | BIT_UNSIGNED]))
            extrinsic_def = self.get_unsigned_extrinsic_def(DEFAULT_EXTRINSIC_VERSION)

        self.arguments = extrinsic_def.arguments

        data += extrinsic_def.new().encode(value)

        # Wrap payload as a Bytes
        data = Bytes.new().encode(data.data)

        return data

    def decode(self, data: ScaleBytes) -> dict:
        # Unwrap data
        data = ScaleBytes(Bytes.decode(data))

        # Get extrinsic version information encoding in the first byte
        version_info = int.from_bytes(data.get_next_bytes(1), byteorder='little')

        signed = (version_info & BIT_SIGNED) == BIT_SIGNED
        version = version_info & UNMASK_VERSION

        if signed:
            extrinsic_def = self.get_signed_extrinsic_def(version)
        else:
            extrinsic_def = self.get_unsigned_extrinsic_def(version)

        self.arguments = extrinsic_def.arguments

        return extrinsic_def.decode(data)

    def example_value(self, _recursion_level: int = 0, max_recursion: int = TYPE_DECOMP_MAX_RECURSIVE):
        return '<Extrinsic>'


class GenericExtrinsic(ScaleType):
    @property
    def extrinsic_hash(self):
        if self.data is not None:
            return blake2b(self.data.data, digest_size=32).digest()


class GenericEra(EnumType):

    def __init__(self, type_def: ScaleTypeDef):
        self.period = None
        self.phase = None
        super().__init__(type_def)

    def decode(self, data: ScaleBytes) -> dict:

        self._data = data
        self._data_start_offset = data.offset

        enum_byte = data.get_next_bytes(1)
        if enum_byte == b'\x00':
            self.value_serialized = 'Immortal'
        else:

            encoded = int(enum_byte.hex(), base=16) + (int(data.get_next_bytes(1).hex(), base=16) << 8)
            self.period = 2 << (encoded % (1 << 4))
            quantize_factor = max(1, (self.period >> 12))
            self.phase = (encoded >> 4) * quantize_factor
            if self.period >= 4 and self.phase < self.period:

                self.value_serialized = {'Mortal': (self.period, self.phase)}
            else:
                raise ScaleDecodeException('Invalid phase and period: {}, {}'.format(self.phase, self.period))

        self.value_object = self.deserialize(self.value_serialized)

        self._data_end_offset = data.offset

        return self.value_serialized

    def _tuple_from_dict(self, value):
        if 'period' not in value:
            raise ScaleEncodeException("Value missing required field 'period' in dict Era")
        period = value['period']

        if 'phase' in value:
            return (period, value['phase'])

        # If phase not specified explicitly, let the user specify the current block,
        # and calculate the phase from that.
        if 'current' not in value:
            raise ScaleEncodeException("Dict Era must have one of the fields 'phase' or 'current'")

        current = value['current']

        # Period must be a power of two between 4 and 2**16
        period = max(4, min(1 << 16, next_power_of_two(period)))
        phase = current % period
        quantize_factor = max(1, (period >> 12))
        quantized_phase = (phase // quantize_factor) * quantize_factor

        return (period, quantized_phase)

    def encode(self, value: Union[str, dict, ScaleType]) -> ScaleBytes:

        if value and issubclass(self.__class__, value.__class__):
            # Accept instance of current class directly
            self._data = value.data
            self.value_object = value.value_object
            self.value_serialized = value.value_serialized
            return value.data

        if type(value) is dict:
            value = value.copy()

        self.value_serialized = value

        if value == 'Immortal':
            self.period = None
            self.phase = None
            self._data = ScaleBytes('0x00')
        elif type(value) is dict:
            if 'Mortal' not in value and 'Immortal' not in value:
                value = {'Mortal': value}
            if type(value['Mortal']) is dict:
                value['Mortal'] = self._tuple_from_dict(value['Mortal'])

            period, phase = value['Mortal']
            if not isinstance(phase, int) or not isinstance(period, int):
                raise ScaleEncodeException("Phase and period must be ints")
            if phase > period:
                raise ScaleEncodeException("Phase must be less than period")
            self.period = period
            self.phase = phase
            quantize_factor = max(period >> 12, 1)
            encoded = min(15, max(1, trailing_zeros(period) - 1)) | ((phase // quantize_factor) << 4)
            self._data = ScaleBytes(encoded.to_bytes(length=2, byteorder='little', signed=False))
        else:
            raise ScaleEncodeException("Incorrect value for Era")

        self._data_start_offset = self._data.offset
        self._data_end_offset = self._data.length

        return self._data

    def is_immortal(self) -> bool:
        """Returns true if the era is immortal, false if mortal."""
        return self.period is None or self.phase is None

    def birth(self, current: int) -> int:
        """Gets the block number of the start of the era given, with `current`
        as the reference block number for the era, normally included as part
        of the transaction.
        """
        if self.is_immortal():
            return 0
        return (max(current, self.phase) - self.phase) // self.period * self.period + self.phase

    def death(self, current: int) -> int:
        """Gets the block number of the first block at which the era has ended.

        If the era is immortal, 2**64 - 1 (the maximum unsigned 64-bit integer) is returned.
        """
        if self.is_immortal():
            return 2**64 - 1
        return self.birth(current) + self.period


class Era(Enum):

    def __init__(self):
        super().__init__(Immortal=None, Mortal=Tuple(Period, Phase))
        self.scale_type_cls = GenericEra


class GenericMetadataVX(ScaleType):

    def migrate_to_latest(self):
        pass


class GenericMetadataV14(GenericMetadataVX):
    pass


class MetadataAllType(EnumType):
    """
    Enum that contains a Metadata version.

    E.g.  `{"V14": MetadataV14}`
    """

    @property
    def pallets(self):
        metadata_obj = self.value_object[1]
        return metadata_obj.value_object['pallets'].value_object

    @property
    def portable_registry(self):
        return self.value_object[1].value_object['types']

    def get_event(self, pallet_index, event_index):
        pass

    def get_metadata_pallet(self, name: str) -> Optional['PalletMetadataType']:
        for pallet in self[1]['pallets']:
            if pallet.value['name'] == name:
                return pallet


class GenericMetadataVersioned(ScaleType):
    """
    Tuple that contains a backwards compatible MetadataAll type
    """

    def get_module_error(self, module_index, error_index):
        if self.portable_registry:
            for module in self.pallets:
                if module['index'] == module_index and module.errors:
                    return module.errors[error_index]
        else:
            return self.value_object[1].error_index.get(f'{module_index}-{error_index}')

    def get_metadata(self):
        return self.value_object[1]

    @property
    def portable_registry(self) -> 'PortableRegistry':
        return self.get_metadata().portable_registry

    @property
    def pallets(self):
        return self.get_metadata().pallets

    @property
    def apis(self) -> List['GenericRuntimeApiMetadata']:
        if self.get_metadata().index >= 15:
            return self.get_metadata()[1]['apis'].value_object
        else:
            apis = Vec(RuntimeApiMetadataV14).new()
            apis.encode(get_apis())
            return apis.value_object

    def get_api(self, name: str) -> 'GenericRuntimeApiMetadata':
        for api in self.apis:
            if name == api.value['name']:
                return api
        raise ValueError(f"Runtime Api '{name}' not found")

    def get_metadata_pallet(self, name: str) -> 'PalletMetadataType':
        return self.get_metadata().get_metadata_pallet(name)

    def get_pallet_by_index(self, index: int):

        for pallet in self.pallets:
            if pallet.value['index'] == index:
                return pallet

        raise ValueError(f'Pallet for index "{index}" not found')

    def get_signed_extensions(self) -> dict:

        signed_extensions = {}

        if self.portable_registry:
            for se in self.value_object[1][1]['extrinsic']['signed_extensions'].value:
                signed_extensions[se['identifier']] = {
                    'extrinsic': self.portable_registry.get_scale_type_def(se['ty']),
                    'additional_signed': self.portable_registry.get_scale_type_def(se['additional_signed'])
                }

        return signed_extensions

    def get_call_type_def(self) -> ScaleTypeDef:

        extrinsic_registry_type = self.get_extrinsic_registry_type()
        for param in extrinsic_registry_type.value['params']:
            if param['name'] == 'Call':
                return self.portable_registry.get_scale_type_def(param['type']).impl(GenericCall)

    def get_extrinsic_registry_type(self) -> GenericRegistryType:
        si_type_id = self.value_object[1][1]['extrinsic']['ty'].value
        return self.portable_registry.get_registry_type(si_type_id)

    def get_extrinsic_type_def(self) -> ScaleTypeDef:
        return Extrinsic(self)

    def get_address_type_def(self) -> ScaleTypeDef:
        extrinsic_registry_type = self.get_extrinsic_registry_type()
        for param in extrinsic_registry_type.value['params']:
            if param['name'] == 'Address':
                return self.portable_registry.get_scale_type_def(param['type'])

    def get_extrinsic_signature_type_def(self) -> ScaleTypeDef:
        extrinsic_registry_type = self.get_extrinsic_registry_type()
        for param in extrinsic_registry_type.value['params']:
            if param['name'] == 'Signature':
                return self.portable_registry.get_scale_type_def(param['type'])


class PalletMetadataType(ScaleType):

    @property
    def name(self):
        return self.value['name']

    def get_identifier(self):
        return self.value['name']

    @property
    def storage(self) -> Optional[list]:

        storage_functions = self.value_object['storage'].value_object

        if storage_functions:
            pallet_version_sf = StorageEntryMetadataCustom.new()
            pallet_version_sf.encode({
                'name': ':__STORAGE_VERSION__:',
                'modifier': 'Default',
                'type': {'Plain': 'u16'},
                'default': '0x0000',
                'documentation': ['Returns the current pallet version from storage']
            })

            return [pallet_version_sf] + storage_functions['entries'].value_object

    @property
    def calls(self):
        if self.value_object['calls'].value_object:
            return self.value_object['calls'].value_object.calls
        else:
            return []

    @property
    def events(self):
        if self.value_object['event'].value_object:
            return self.value_object['event'].value_object.events
        else:
            return []

    @property
    def errors(self):
        if self.value_object['error'].value_object:
            return self.value_object['error'].value_object.errors
        else:
            return []

    @property
    def constants(self):
        return self.value_object['constants'].value_object

    def get_storage_function(self, name: str):
        if self.storage:

            # Convert name for well-known PalletVersion storage entry
            if name == 'PalletVersion':
                name = ':__STORAGE_VERSION__:'

            for storage_function in self.storage:
                if storage_function.value['name'] == name:
                    return storage_function


class GenericRuntimeApiMetadata(ScaleType):

    @property
    def name(self):
        return self.value['name']

    @property
    def methods(self):
        return list(self.value_object['methods'])

    def get_method(self, name: str) -> 'GenericRuntimeApiMethodMetadata':
        for method in self.methods:
            if name == method.value['name']:
                return method
        raise ValueError(f"Runtime API method '{self.value['name']}.{name}' not found")


class LegacyRuntimeApiMetadata(GenericRuntimeApiMetadata):
    pass


class GenericRuntimeApiMethodMetadata(ScaleType):

    @property
    def name(self):
        return self.value['name']

    def get_params(self, metadata):
        return [
            {
                'name': p['name'],
                'type_def': metadata.portable_registry.get_scale_type_def(p["type"])
            } for p in self.value['inputs']
        ]

    def get_return_type_def(self, metadata):
        return metadata.portable_registry.get_scale_type_def(self.value['output'])


class LegacyRuntimeApiMethodMetadata(GenericRuntimeApiMethodMetadata):

    def get_params(self, metadata):
        return [{'name': p['name'], 'type_def': get_type_def(p["type"], metadata)} for p in self.value['inputs']]

    def get_return_type_def(self, metadata):
        return get_type_def(self.value['output'], metadata)


class GenericEventMetadata(ScaleType):

    @property
    def name(self):
        return self.value['name']

    @property
    def args(self):
        return self.value_object['args']

    @property
    def docs(self):
        return self.value['documentation']


class GenericErrorMetadata(ScaleType):

    @property
    def name(self):
        return self.value['name']

    @property
    def docs(self):
        return self.value['documentation']


class GenericStorageEntryMetadata(ScaleType):

    def get_value_type_id(self):
        if 'Plain' in self.value['type']:
            return self.value['type']['Plain']
        elif 'Map' in self.value['type']:
            return self.value['type']['Map']['value']
        else:
            raise NotImplementedError()

    def get_key_type_id(self):
        if 'Map' in self.value['type']:
            return self.value['type']['Map']['key']

    def get_params_type_id(self) -> Optional[int]:
        if 'Plain' in self.value['type']:
            return None
        elif 'Map' in self.value['type']:
            return self.value['type']['Map']['key']
        else:
            raise NotImplementedError()

    def get_key_scale_info_definition(self):
        if 'Map' in self.value['type']:
            key_type_string = self.get_type_string_for_type(self.value['type']['Map']['key'])
            nmap_key_scale_type = self.runtime_config.get_decoder_class(key_type_string)

            return nmap_key_scale_type.scale_info_type['def'][0]

    def get_param_hashers(self):
        if 'Plain' in self.value['type']:
            return ['Twox64Concat']
        elif 'Map' in self.value['type']:
            return self.value['type']['Map']['hashers']
        else:
            raise NotImplementedError()

    def get_param_info(self, max_recursion: int = TYPE_DECOMP_MAX_RECURSIVE) -> list:
        """
        Return a type decomposition how to format parameters for current storage function

        Returns
        -------
        list
        """
        param_info = []
        for param_type_string in self.get_params_type_string():
            scale_type = self.runtime_config.create_scale_object(param_type_string)
            param_info.append(scale_type.generate_type_decomposition(max_recursion=max_recursion))

        return param_info

String = String()
Bytes = Bytes()
Type = String
Text = String
H256 = HashDef(256)
H512 = HashDef(512)
Hash = H256
HashMap = Map
BTreeMap = Map
MultiAccountId = GenericAccountId
GenericRuntimeCallDefinition = Enum()
# Extrinsic = GenericExtrinsic
GenericContractExecResult = Enum()
Call = Enum().impl(GenericCall) # TODO .init(scale_type_cls=GenericCall)
BlockNumber = U32
SlotNumber = U64
VrfOutput = Array(U8, 32)
VrfProof = Array(U8, 64)
RawAuraPreDigest = Struct(slot_number=U64)
RawBabePreDigestPrimary = Struct(authority_index=U32, slot_number=SlotNumber, vrf_output=VrfOutput, vrf_proof=VrfProof)
RawBabePreDigestSecondaryPlain = Struct(authority_index=U32, slot_number=SlotNumber)
RawBabePreDigestSecondaryVRF = Struct(authority_index=U32, slot_number=SlotNumber, vrf_output=VrfOutput, vrf_proof=VrfProof)
RawBabePreDigest = Enum(Phantom=None, Primary=RawBabePreDigestPrimary, SecondaryPlain=RawBabePreDigestSecondaryPlain, SecondaryVRF=RawBabePreDigestSecondaryVRF)
# ErrorMetadataV9 = Struct(name=Text, documentation=Vec(Text))
# EventMetadataV9 = Struct(name=Text, args=Vec(Type), documentation=Vec(Text))
# FunctionArgumentMetadataV9 = Struct(name=Text, type=Type)
# FunctionMetadataV9 = Struct(name=Text, args=Vec(FunctionArgumentMetadataV9), documentation=Vec(Text))
# MapTypeV9 = Struct(hasher=StorageHasherV9, key=Type, value=Type, linked=bool)
# MetadataV9 = Struct(modules=Vec(ModuleMetadataV9))
# ModuleConstantMetadataV9 = Struct(name=Text, type=Type, value=Bytes, documentation=Vec(Text))
# StorageEntryModifierV9 = Enum(Optional=None, Default=None, Required=None)
# StorageHasherV9 = Enum(Blake2_128=None, Blake2_256=None, Blake2_128Concat=None, Twox128=None, Twox256=None, Twox64Concat=None)
# DoubleMapTypeV9 = Struct(hasher=StorageHasherV9, key1=Type, key2=Type, value=Type, key2_hasher=StorageHasherV9)
# StorageEntryTypeV9 = Enum(Plain=Type, Map=MapTypeV9, DoubleMap=DoubleMapTypeV9)
# StorageEntryMetadataV9 = Struct(name=String, modifier=StorageEntryModifierV9, type=StorageEntryTypeV9, default=Bytes, documentation=Vec(Text))
# StorageMetadataV9 = Struct(prefix=Text, entries=Vec(StorageEntryMetadataV9))
# ModuleMetadataV9 = Struct(name=Text, storage=Option(StorageMetadataV9), calls=Option(Vec(FunctionMetadataV9)), events=Option(Vec(EventMetadataV9)), constants=Vec(ModuleConstantMetadataV9), errors=Vec(ErrorMetadataV9))
# ErrorMetadataV10 = ErrorMetadataV9
# EventMetadataV10 = EventMetadataV9
# FunctionArgumentMetadataV10 = FunctionArgumentMetadataV9
# FunctionMetadataV10 = FunctionMetadataV9
# MapTypeV10 = Struct(hasher=StorageHasherV10, key=Type, value=Type, linked=bool)
# MetadataV10 = Struct(modules=Vec(ModuleMetadataV10))
# ModuleConstantMetadataV10 = ModuleConstantMetadataV9
# ModuleMetadataV10 = Struct(name=Text, storage=Option(StorageMetadataV10), calls=Option(Vec(FunctionMetadataV10)), events=Option(Vec(EventMetadataV10)), constants=Vec(ModuleConstantMetadataV10), errors=Vec(ErrorMetadataV10))
# StorageEntryModifierV10 = StorageEntryModifierV9
# StorageEntryMetadataV10 = Struct(name=String, modifier=StorageEntryModifierV10, type=StorageEntryTypeV10, default=Bytes, documentation=Vec(Text))
# StorageEntryTypeV10 = Enum(Plain=Type, Map=MapTypeV10, DoubleMap=DoubleMapTypeV10)
# StorageMetadataV10 = Struct(prefix=Text, entries=Vec(StorageEntryMetadataV10))
# StorageHasherV10 = Enum(Blake2_128=None, Blake2_256=None, Blake2_128Concat=None, Twox128=None, Twox256=None, Twox64Concat=None)
# DoubleMapTypeV10 = Struct(hasher=StorageHasherV10, key1=Type, key2=Type, value=Type, key2_hasher=StorageHasherV10)
# DoubleMapTypeV11 = Struct(hasher=StorageHasherV11, key1=Type, key2=Type, value=Type, key2_hasher=StorageHasherV11)
# ErrorMetadataV11 = ErrorMetadataV10
# EventMetadataV11 = EventMetadataV10
# ExtrinsicMetadataV11 = Struct(version=U8, signed_extensions=Vec(Text))
# FunctionArgumentMetadataV11 = FunctionArgumentMetadataV10
# FunctionMetadataV11 = FunctionMetadataV10
# MapTypeV11 = Struct(hasher=StorageHasherV11, key=Type, value=Type, linked=bool)
# MetadataV11 = Struct(modules=Vec(ModuleMetadataV11), extrinsic=ExtrinsicMetadataV11)
# ModuleConstantMetadataV11 = ModuleConstantMetadataV10
# ModuleMetadataV11 = Struct(name=Text, storage=Option(StorageMetadataV11), calls=Option(Vec(FunctionMetadataV11)), events=Option(Vec(EventMetadataV11)), constants=Vec(ModuleConstantMetadataV11), errors=Vec(ErrorMetadataV11))
# StorageEntryModifierV11 = StorageEntryModifierV10
# StorageEntryMetadataV11 = Struct(name=Text, modifier=StorageEntryModifierV11, type=StorageEntryTypeV11, default=Bytes, documentation=Vec(Text))
# StorageEntryTypeV11 = Enum(Plain=Type, Map=MapTypeV11, DoubleMap=DoubleMapTypeV11)
# StorageMetadataV11 = Struct(prefix=Text, entries=Vec(StorageEntryMetadataV11))
# StorageHasherV11 = Enum(Blake2_128=None, Blake2_256=None, Blake2_128Concat=None, Twox128=None, Twox256=None, Twox64Concat=None, Identity=None)
# DoubleMapTypeV12 = DoubleMapTypeV11
# ErrorMetadataV12 = ErrorMetadataV11
# EventMetadataV12 = EventMetadataV11
# ExtrinsicMetadataV12 = ExtrinsicMetadataV11
# FunctionArgumentMetadataV12 = FunctionArgumentMetadataV11
# FunctionMetadataV12 = FunctionMetadataV11
# MapTypeV12 = MapTypeV11
# MetadataV12 = Struct(modules=Vec(ModuleMetadataV12), extrinsic=ExtrinsicMetadataV12)
# ModuleConstantMetadataV12 = ModuleConstantMetadataV11
# ModuleMetadataV12 = Struct(name=Text, storage=Option(StorageMetadataV12), calls=Option(Vec(FunctionMetadataV12)), events=Option(Vec(EventMetadataV12)), constants=Vec(ModuleConstantMetadataV12), errors=Vec(ErrorMetadataV12), index=U8)
# StorageEntryModifierV12 = StorageEntryModifierV11
# StorageEntryMetadataV12 = StorageEntryMetadataV11
# StorageEntryTypeV12 = StorageEntryTypeV11
# StorageMetadataV12 = StorageMetadataV11
# StorageHasherV12 = StorageHasherV11
# DoubleMapTypeV13 = DoubleMapTypeV12
# ErrorMetadataV13 = ErrorMetadataV12
# EventMetadataV13 = EventMetadataV12
# ExtrinsicMetadataV13 = ExtrinsicMetadataV12
# FunctionArgumentMetadataV13 = FunctionArgumentMetadataV12
# FunctionMetadataV13 = FunctionMetadataV12
# MapTypeV13 = MapTypeV12
# MetadataV13 = Struct(modules=Vec(ModuleMetadataV13), extrinsic=ExtrinsicMetadataV13)
# ModuleConstantMetadataV13 = ModuleConstantMetadataV9
# ModuleMetadataV13 = Struct(name=Text, storage=Option(StorageMetadataV13), calls=Option(Vec(FunctionMetadataV13)), events=Option(Vec(EventMetadataV13)), constants=Vec(ModuleConstantMetadataV13), errors=Vec(ErrorMetadataV13), index=U8)
# NMapTypeV13 = Struct(keys=Vec(Type), hashers=Vec(StorageHasherV13), value=Type)
# StorageEntryModifierV13 = StorageEntryModifierV12
# StorageEntryMetadataV13 = Struct(name=String, modifier=StorageEntryModifierV13, type=StorageEntryTypeV13, default=Bytes, documentation=Vec(Text))
# StorageEntryTypeV13 = Enum(Plain=Type, Map=MapTypeV13, DoubleMap=DoubleMapTypeV13, NMap=NMapTypeV13)
# StorageMetadataV13 = Struct(prefix=Text, entries=Vec(StorageEntryMetadataV13))
# StorageHasherV13 = StorageHasherV12
# DoubleMapTypeLatest = DoubleMapTypeV13
# ErrorMetadataLatest = ErrorMetadataV13
# EventMetadataLatest = EventMetadataV13
# ExtrinsicMetadataLatest = ExtrinsicMetadataV13
# FunctionArgumentMetadataLatest = FunctionArgumentMetadataV13
# FunctionMetadataLatest = FunctionMetadataV13
# MapTypeLatest = MapTypeV13
# MetadataLatest = MetadataV13
# ModuleConstantMetadataLatest = ModuleConstantMetadataV13
# ModuleMetadataLatest = ModuleMetadataV13
# NMapTypeLatest = NMapTypeV13
# StorageEntryMetadataLatest = StorageEntryMetadataV13
# StorageEntryModifierLatest = StorageEntryModifierV13
# StorageEntryTypeLatest = StorageEntryTypeV13
# StorageMetadataLatest = StorageMetadataV13
# StorageHasher = StorageHasherV13
SiLookupTypeId = Compact(U32)
StorageHasherV13 = Enum(
    Blake2_128=None, Blake2_256=None, Blake2_128Concat=None, Twox128=None, Twox256=None, Twox64Concat=None,
    Identity=None
)
StorageEntryModifierV13 = Enum(Optional=None, Default=None, Required=None)
MapTypeV14 = Struct(
    hashers=Vec(StorageHasherV13), key=SiLookupTypeId, value=SiLookupTypeId
)
StorageEntryTypeV14 = Enum(Plain=SiLookupTypeId, Map=MapTypeV14)
StorageEntryMetadataV14 = Struct(
    name=String, modifier=StorageEntryModifierV13, type=StorageEntryTypeV14, default=Bytes, documentation=Vec(Text)
).impl(GenericStorageEntryMetadata)
StorageMetadataV14 = Struct(prefix=Text, entries=Vec(StorageEntryMetadataV14))
PalletCallMetadataV14 = Struct(ty=SiLookupTypeId)
FunctionArgumentMetadataV14 = Struct(name=Text, type=SiLookupTypeId)
FunctionMetadataV14 = Struct(name=String, args=Vec(FunctionArgumentMetadataV14), documentation=Vec(String))
PalletEventMetadataV14 = Struct(ty=SiLookupTypeId)
PalletConstantMetadataV14 = Struct(name=String, type=SiLookupTypeId, value=Bytes, documentation=Vec(String))
PalletErrorMetadataV14 = Struct(ty=SiLookupTypeId)

PalletMetadataV14 = Struct(
    name=Text, storage=Option(StorageMetadataV14), calls=Option(PalletCallMetadataV14),
    event=Option(PalletEventMetadataV14), constants=Vec(PalletConstantMetadataV14),
    error=Option(PalletErrorMetadataV14), index=U8
).impl(PalletMetadataType)

StorageEntryTypeCustom = Enum(Plain=String)
StorageEntryMetadataCustom = Struct(
    name=String, modifier=StorageEntryModifierV13, type=StorageEntryTypeCustom, default=Bytes, documentation=Vec(Text)
).impl(GenericStorageEntryMetadata)


SignedExtensionMetadataV14 = Struct(identifier=String, ty=SiLookupTypeId, additional_signed=SiLookupTypeId)
ExtrinsicMetadataV14 = Struct(ty=SiLookupTypeId, version=U8, signed_extensions=Vec(SignedExtensionMetadataV14))
TypeParameter = Struct(name=String, type=Option(SiLookupTypeId))
Field = Struct(name=Option(String), type=SiLookupTypeId, typeName=Option(String), docs=Vec(String))
TypeDefComposite = Struct(fields=Vec(Field))
Variant = Struct(name=String, fields=Vec(Field), index=U8, docs=Vec(String))
TypeDefVariant = Struct(variants=Vec(Variant))
TypeDefSequence = Struct(type=SiLookupTypeId)
TypeDefArray = Struct(len=U32, type=SiLookupTypeId)
TypeDefTuple = Vec(SiLookupTypeId)
TypeDefPrimitive = Enum(
    bool=None, char=None, str=None, U8=None, u16=None, u32=None, u64=None, u128=None, u256=None, i8=None, i16=None,
    i32=None, i64=None, i128=None, i256=None
)
TypeDefCompact = Struct(type=SiLookupTypeId)
TypeDefPhantom = Null
TypeDefBitSequence = Struct(bit_store_type=SiLookupTypeId, bit_order_type=SiLookupTypeId)
TypeDef = Enum(
    composite=TypeDefComposite, variant=TypeDefVariant, sequence=TypeDefSequence, array=TypeDefArray,
    tuple=TypeDefTuple, primitive=TypeDefPrimitive, compact=TypeDefCompact, bitsequence=TypeDefBitSequence
)
RegistryType = Struct(
    path=Vec(String), params=Vec(TypeParameter), def_=TypeDef, docs=Vec(String)
).impl(
    scale_type_cls=GenericRegistryType
)

PortableType = Struct(id=SiLookupTypeId, type=RegistryType)
PortableRegistry = Struct(types=Vec(PortableType)).impl(GenericPortableRegistry)

RuntimeApiMethodParamMetadataV14 = Struct(name=Text, type=String)

RuntimeApiMethodMetadataV14 = Struct(
    name=Text, inputs=Vec(RuntimeApiMethodParamMetadataV14), output=String, docs=Vec(Text)
).impl(LegacyRuntimeApiMethodMetadata)

RuntimeApiMetadataV14 = Struct(
    name=Text, methods=Vec(RuntimeApiMethodMetadataV14), docs=Vec(Text)
).impl(GenericRuntimeApiMetadata)


MetadataV14 = Struct(
    types=PortableRegistry, pallets=Vec(PalletMetadataV14), extrinsic=ExtrinsicMetadataV14, runtime_type=SiLookupTypeId
).impl(GenericMetadataV14)

PalletMetadataV15 = Struct(
    name=Text,
    storage=Option(StorageMetadataV14),
    calls=Option(PalletCallMetadataV14),
    event=Option(PalletEventMetadataV14),
    constants=Vec(PalletConstantMetadataV14),
    error=Option(PalletErrorMetadataV14),
    index=U8,
    docs=Vec(Text)
).impl(PalletMetadataType)

ExtrinsicMetadataV15 = Struct(
    version=U8,
    address_type=SiLookupTypeId,
    call_type=SiLookupTypeId,
    signature_type=SiLookupTypeId,
    extra_type=SiLookupTypeId,
    signed_extensions=Vec(SignedExtensionMetadataV14)
)
OuterEnums15 = Struct(call_type=SiLookupTypeId, event_type=SiLookupTypeId, error_type=SiLookupTypeId)
CustomValueMetadata15 = Bytes
CustomMetadata15 = BTreeMap(Text, CustomValueMetadata15)
RuntimeApiMethodParamMetadataV15 = Struct(name=Text, type=SiLookupTypeId)
RuntimeApiMethodMetadataV15 = Struct(
    name=Text, inputs=Vec(RuntimeApiMethodParamMetadataV15), output=SiLookupTypeId, docs=Vec(Text)
).impl(GenericRuntimeApiMethodMetadata)

RuntimeApiMetadataV15 = Struct(
    name=Text, methods=Vec(RuntimeApiMethodMetadataV15), docs=Vec(Text)
).impl(GenericRuntimeApiMetadata)

MetadataV15 = Struct(
    types=PortableRegistry,
    pallets=Vec(PalletMetadataV15),
    extrinsic=ExtrinsicMetadataV15,
    runtime_type=SiLookupTypeId,
    apis=Vec(RuntimeApiMetadataV15),
    outer_enums=OuterEnums15,
    custom=Vec(CustomMetadata15)
)

MetadataAll = Enum(
    V0=TypeNotSupported("MetadataV0"),
    V1=TypeNotSupported("MetadataV1"),
    V2=TypeNotSupported("MetadataV2"),
    V3=TypeNotSupported("MetadataV3"),
    V4=TypeNotSupported("MetadataV4"),
    V5=TypeNotSupported("MetadataV5"),
    V6=TypeNotSupported("MetadataV6"),
    V7=TypeNotSupported("MetadataV7"),
    V8=TypeNotSupported("MetadataV8"),
    V9=TypeNotSupported("MetadataV9"),
    V10=TypeNotSupported("MetadataV10"),
    V11=TypeNotSupported("MetadataV11"),
    V12=TypeNotSupported("MetadataV12"),
    V13=TypeNotSupported("MetadataV13"),
    V14=MetadataV14,
    V15=MetadataV15
).impl(MetadataAllType)

MetadataVersioned = Tuple(Array(U8, 4), MetadataAll).impl(GenericMetadataVersioned)

# AccountId = AccountIdDef()
# MultiAddress = MultiAddressEnum()
Address = MultiAddress
Index = U32
Balance = U128
EcdsaSignature = Array(U8, 65)
Ed25519Signature = H512
Sr25519Signature = H512
MultiSignature = Enum(Ed25519=Ed25519Signature, Sr25519=Sr25519Signature, Ecdsa=EcdsaSignature)
ExtrinsicSignature = MultiSignature
Period = U64
Phase = U64
# Era = Enum(Immortal=None, Mortal=Tuple(Period, Phase)).impl(GenericEra)
ExtrinsicV4 = Struct(address=Address, signature=ExtrinsicSignature, era=Era, nonce=Compact(Index), tip=Compact(Balance), call=Call)

Inherent = Struct(call=Call)
# Signature = H512

# AnySignature = H512


ExtrinsicPayloadValue = Struct(call=Call, era=Era, nonce=Compact(Index), tip=Compact(Balance), spec_version=U32, transaction_version=U32, genesis_hash=Hash, block_hash=Hash)
#
# WeightV1 = U64
# WeightV2 = Struct(ref_time=Compact(U64), proof_size=Compact(U64))
# Weight = WeightV2 # TODO
# ContractExecResultTo267 = Struct(gas_consumed=Weight, gas_required=Weight, storage_deposit=StorageDeposit, debug_message=Bytes, result=ContractExecResultResult)
# ContractExecResultTo269 = Struct(gas_consumed=Weight, gas_required=Weight, storage_deposit=StorageDeposit, debug_message=Bytes, result=ContractExecResultResult, events=Option(Vec(frame_system::eventrecord)))
# ContractExecResultResult = Enum(Ok=ContractExecResultOk, Error=sp_runtime::dispatcherror)
# ContractExecResultOk = Struct(flags=ContractCallFlags, data=Bytes)
# ContractExecResultTo260 = Enum(Success=ContractExecResultSuccessTo260, Error=None)
# ContractExecResultSuccessTo260 = Struct(flags=U32, data=Bytes, gas_consumed=U64)
# ContractExecResult = ContractExecResultTo267
# RuntimeCallDefinition = Struct(api=String, method=String, description=String, params=Vec(RuntimeCallDefinitionParam), type=String)
# RuntimeCallDefinitionParam = Struct(name=String, type=String)


