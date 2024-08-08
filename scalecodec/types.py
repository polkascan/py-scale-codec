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
import enum

import math
import struct
from typing import Union, Optional

from scalecodec.base import ScaleType, ScaleBytes, ScalePrimitive, ScaleTypeDef
from scalecodec.constants import TYPE_DECOMP_MAX_RECURSIVE
from scalecodec.exceptions import ScaleEncodeException, ScaleDecodeException, ScaleDeserializeException, \
    ScaleSerializeException


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

    def _encode(self, value) -> ScaleBytes:

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

    def _encode(self, value) -> ScaleBytes:

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


class Float(ScalePrimitive):

    def __init__(self, bits: int):
        super().__init__()
        self.bits = bits
        self.byte_count = int(self.bits / 8)
        self.struct_format = 'f' if self.bits == 32 else 'd'

    def decode(self, data: ScaleBytes) -> int:
        return struct.unpack(self.struct_format, data.get_next_bytes(self.byte_count))[0]

    def _encode(self, value: float) -> ScaleBytes:
        if type(value) is not float:
            raise ScaleEncodeException(f'{value} is not a float')

        return ScaleBytes(struct.pack(self.struct_format, value))

    def serialize(self, value: float) -> float:
        return value

    def deserialize(self, value: float) -> float:
        if type(value) is not float:
            raise ScaleDeserializeException('Value must be an float')
        return value

    def example_value(self, _recursion_level: int = 0, max_recursion: int = TYPE_DECOMP_MAX_RECURSIVE):
        return float(self.bits)


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
F32 = Float(32)
F64 = Float(64)


class Bool(ScalePrimitive):

    def decode(self, data: ScaleBytes) -> bool:

        bool_data = data.get_next_bytes(1)
        if bool_data not in [b'\x00', b'\x01']:
            raise ScaleDecodeException('Invalid value for datatype "bool"')
        return bool_data == b'\x01'

    def _encode(self, value: bool) -> ScaleBytes:
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

    def _encode(self, value: any) -> ScaleBytes:
        return ScaleBytes(bytearray())

    def serialize(self, value: any) -> any:
        return None

    def deserialize(self, value: any) -> any:
        return None

    def example_value(self, _recursion_level: int = 0, max_recursion: int = TYPE_DECOMP_MAX_RECURSIVE):
        return None


Null = NullType()


class StructObject(ScaleType):
    def encode(self, value: Optional[Union[dict, tuple]] = None) -> ScaleBytes:
        if type(value) is tuple:
            # Convert tuple to dict
            try:
                value = {key: value[idx] for idx, key in enumerate(self.type_def.arguments.keys())}
            except IndexError:
                raise ScaleEncodeException("Not enough items in tuple to convert to dict")
        return super().encode(value)


class Struct(ScaleTypeDef):

    arguments = None
    scale_type_cls = StructObject

    def __init__(self, **kwargs):
        if len(kwargs) > 0:
            self.arguments = {key.rstrip('_'): value for key, value in kwargs.items()}
        super().__init__()

    def _encode(self, value: dict) -> ScaleBytes:

        data = ScaleBytes(bytearray())
        for name, scale_obj in self.arguments.items():

            if name not in value:
                raise ScaleEncodeException(f'Argument "{name}" of Struct is missing in given value')

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
        if value is None:
            raise ScaleSerializeException('Value cannot be None')
        return {k: obj.value for k, obj in value.items()}

    def deserialize(self, value: dict) -> dict:
        value_object = {}

        for key, scale_def in self.arguments.items():
            if key in value:
                scale_obj = scale_def.new()

                scale_obj.value_serialized = value[key]
                scale_obj.deserialize(value[key])

                value_object[key] = scale_obj
            else:
                raise ScaleDeserializeException(f'Argument "{key}" of Struct is missing in given value')

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

    def _encode(self, value: tuple) -> ScaleBytes:
        if type(value) is not tuple:
            value = (value,)

        data = ScaleBytes(bytearray())
        for idx, scale_obj in enumerate(self.values):

            data += scale_obj.new().encode(value[idx])
        return data

    def decode(self, data: ScaleBytes) -> tuple:
        value = ()

        for scale_def in self.values:
            scale_obj = scale_def.new()

            scale_obj.decode(data)

            if len(self.values) == 1:
                return scale_obj

            value += (scale_obj,)

        return value

    def serialize(self, value: Union[tuple, ScaleType]) -> tuple:
        if issubclass(value.__class__, ScaleType):
            return value.value

        return tuple((i.value for i in value))

    def deserialize(self, value: tuple) -> tuple:

        if type(value) is not tuple:
            value = (value,)

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

    def _encode(self, value: Union[str, dict]) -> ScaleBytes:

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

        if isinstance(value, enum.Enum):
            value = {value.name: None}

        if len(list(value.items())) != 1:
            raise ScaleDeserializeException("Only one variant can be specified for enums")

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

    def _encode(self, value: any) -> ScaleBytes:
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

    def _encode(self, value: int) -> ScaleBytes:

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

    def _encode(self, value: list) -> ScaleBytes:

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

    def _encode(self, value: Union[list, str, int]) -> ScaleBytes:

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


class ArrayObject(ScaleType):

    def to_bytes(self) -> bytes:
        if self.type_def.type_def is not U8:
            raise ScaleDeserializeException('Only an Array of U8 can be represented as bytes')
        return self.value_object


class Array(ScaleTypeDef):

    scale_type_cls = ArrayObject

    def __init__(self, type_def: ScaleTypeDef, length: int):
        self.type_def = type_def
        self.length = length
        super().__init__()

    def _encode(self, value: Union[list, str, bytes]) -> ScaleBytes:

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
                data += self.type_def.encode(item, external_call=False)

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

    def deserialize(self, value: Union[list, str, bytes, bytearray]) -> Union[list, bytes]:

        if type(value) not in [list, str, bytes, bytearray]:
            raise ScaleDeserializeException('value should be of type list, str or bytes')

        if type(value) is str:
            if value[0:2] == '0x':
                value = bytes.fromhex(value[2:])
            else:
                value = value.encode()

        if len(value) != self.length:
            raise ScaleDeserializeException('Length of array does not match size of value')

        if type(value) is bytearray:
            value = bytes(value)

        if type(value) is bytes:
            if self.type_def is not U8:
                raise ScaleDeserializeException('Only an Array of U8 can be represented as (hex)bytes')

            return value

        if type(value) is list:

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

    def _encode(self, value: list) -> ScaleBytes:
        # Encode length of Vec
        data = Compact().encode(len(value), external_call=False)

        for item_key, item_value in value:
            data += self.key_def.encode(item_key, external_call=False)
            data += self.value_def.encode(item_value, external_call=False)

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
        output = []
        for k, v in value:
            if type(k) is ScaleType and type(v) is ScaleType:
                output.append((k.value_serialized, v.value_serialized))
            else:
                output.append((k, v))
        return output

    def deserialize(self, value: list) -> list:
        return [(self.key_def.deserialize(k), self.value_def.deserialize(v)) for k, v in value]


class BytesDef(ScaleTypeDef):
    """
    A variable collection of bytes, stored as an `Vec<u8>`
    """

    def _encode(self, value: Union[str, bytes, bytearray, list]) -> ScaleBytes:

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

    def deserialize(self, value: Union[bytes, str, list]) -> bytes:

        if type(value) in (list, bytearray):
            value = bytes(value)

        elif type(value) is str:
            if value[0:2] == '0x':
                value = bytes.fromhex(value[2:])
            else:
                value = value.encode('utf-8')

        if type(value) is not bytes:
            raise ScaleDeserializeException(f'Cannot deserialize type "{type(value)}"')

        return value

    def example_value(self, _recursion_level: int = 0, max_recursion: int = TYPE_DECOMP_MAX_RECURSIVE):
        return b'Bytes'


class StringDef(BytesDef):
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


class HashDefObject(ScaleType):
    def to_bytes(self) -> bytes:
        return self.value_object


class HashDef(ScaleTypeDef):

    scale_type_cls = HashDefObject

    def __init__(self, bits: int):
        super().__init__()
        self.bits = bits
        self.byte_count = int(self.bits / 8)

    def decode(self, data: ScaleBytes) -> bytes:
        return data.get_next_bytes(self.byte_count)

    def _encode(self, value: Union[str, bytes]) -> ScaleBytes:

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

    def deserialize(self, value: Union[str, bytes, bytearray]) -> bytes:
        if type(value) is str:
            value = bytes.fromhex(value[2:])

        if type(value) is bytearray:
            value = bytes(value)

        if type(value) is not bytes:
            raise ScaleDeserializeException('value should be of type str or bytes')

        return value

    def example_value(self, _recursion_level: int = 0, max_recursion: int = TYPE_DECOMP_MAX_RECURSIVE):
        return f'0x{str(self.byte_count).zfill(2) * self.byte_count}'


String = StringDef()
Bytes = BytesDef()
Type = String
Text = String
H256 = HashDef(256)
H512 = HashDef(512)
Hash = H256
HashMap = Map
BTreeMap = Map
