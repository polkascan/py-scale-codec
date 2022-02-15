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
import math
import warnings
from datetime import datetime
from hashlib import blake2b
from typing import Union

from scalecodec.utils.ss58 import ss58_decode_account_index, ss58_decode, ss58_encode, is_valid_ss58_address

from scalecodec.base import ScaleType, ScaleBytes
from scalecodec.exceptions import InvalidScaleTypeValueException, MetadataCallFunctionNotFound
from scalecodec.utils.math import trailing_zeros, next_power_of_two


class Compact(ScaleType):

    def __init__(self, data=None, **kwargs):
        self.compact_length = 0
        self.compact_bytes = None
        super().__init__(data, **kwargs)

    def process_compact_bytes(self):
        compact_byte = self.get_next_bytes(1)
        try:
            byte_mod = compact_byte[0] % 4
        except IndexError:
            raise InvalidScaleTypeValueException("Invalid byte for Compact")

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
            self.compact_bytes = compact_byte + self.get_next_bytes(self.compact_length - 1)
        else:
            self.compact_bytes = self.get_next_bytes(self.compact_length - 1)

        return self.compact_bytes

    def process(self):
        self.process_compact_bytes()

        if self.compact_length <= 4:
            return int(int.from_bytes(self.compact_bytes, byteorder='little') / 4)
        else:
            return int.from_bytes(self.compact_bytes, byteorder='little')

    def process_encode(self, value):

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
                raise ValueError('{} out of range'.format(value))


class CompactU32(Compact):
    """
    Specialized composite implementation for performance improvement
    """

    type_string = 'Compact<u32>'

    def process(self):
        self.process_compact_bytes()

        if self.compact_length <= 4:
            return int(int.from_bytes(self.compact_bytes, byteorder='little') / 4)
        else:
            return int.from_bytes(self.compact_bytes, byteorder='little')

    def process_encode(self, value):

        if value <= 0b00111111:
            return ScaleBytes(bytearray(int(value << 2).to_bytes(1, 'little')))

        elif value <= 0b0011111111111111:
            return ScaleBytes(bytearray(int((value << 2) | 0b01).to_bytes(2, 'little')))

        elif value <= 0b00111111111111111111111111111111:

            return ScaleBytes(bytearray(int((value << 2) | 0b10).to_bytes(4, 'little')))

        else:
            for bytes_length in range(4, 68):
                if 2 ** (8 * (bytes_length-1)) <= value < 2 ** (8 * bytes_length):
                    return ScaleBytes(bytearray(((bytes_length - 4) << 2 | 0b11).to_bytes(1, 'little') + value.to_bytes(bytes_length, 'little')))
            else:
                raise ValueError('{} out of range'.format(value))


class Option(ScaleType):
    def process(self):

        option_byte = self.get_next_bytes(1)

        if self.sub_type and option_byte != b'\x00':
            self.value_object = self.process_type(self.sub_type)
            return self.value_object.value

        return None

    def process_encode(self, value):

        if value is not None and self.sub_type:
            sub_type_obj = self.runtime_config.create_scale_object(self.sub_type)
            return ScaleBytes('0x01') + sub_type_obj.encode(value)

        return ScaleBytes('0x00')

    @classmethod
    def process_scale_info_definition(cls, scale_info_definition: 'GenericRegistryType', prefix: str):
        cls.sub_type = f"{prefix}::{scale_info_definition.value['params'][0]['type']}"


class Bytes(ScaleType):

    type_string = 'Vec<u8>'

    def process(self):

        length = self.process_type('Compact<u32>').value
        value = self.get_next_bytes(length)

        self.value_object = value

        try:
            return value.decode()
        except UnicodeDecodeError:
            return '0x{}'.format(value.hex())

    def process_encode(self, value):
        string_length_compact = CompactU32()

        if type(value) is str:
            if value[0:2] == '0x':
                # TODO implicit HexBytes conversion can have unexpected result if string is actually starting with '0x'
                value = bytes.fromhex(value[2:])
            else:
                value = value.encode()

        elif type(value) in (bytearray, list):
            value = bytes(value)

        if type(value) is not bytes:
            raise ValueError(f'Cannot encode type "{type(value)}"')

        data = string_length_compact.encode(len(value))
        data += value

        return data

    def serialize(self):
        return f'0x{self.value_object.hex()}'


class Str(Bytes):
    def serialize(self):
        return self.value


class String(Str):
    pass


class OptionBytes(ScaleType):

    type_string = 'Option<Vec<u8>>'

    def process(self):

        option_byte = self.get_next_bytes(1)

        if option_byte != b'\x00':
            return self.process_type('Bytes').value

        return None

    def process_encode(self, value):

        if value is not None:
            sub_type_obj = Bytes()
            return ScaleBytes('0x01') + sub_type_obj.encode(value)

        return ScaleBytes('0x00')


class HexBytes(ScaleType):

    def __init__(self, *args, **kwargs):
        self.length_obj = None
        super().__init__(*args, **kwargs)

    def process(self):

        self.length_obj = self.process_type('Compact<u32>')

        return '0x{}'.format(self.get_next_bytes(self.length_obj.value).hex())

    def process_encode(self, value):

        if value[0:2] != '0x':
            raise ValueError('HexBytes value should start with "0x"')

        value = bytes.fromhex(value[2:])

        string_length_compact = CompactU32()
        data = string_length_compact.encode(len(value))
        data += value
        return data


class CallBytes(ScaleType):

    def process(self):
        raise NotImplementedError()

    def process_encode(self, value):
        return bytes.fromhex(value[2:])


class RawBytes(ScaleType):

    type_string = '&[u8]'

    def process(self):
        self.value_object = self.get_remaining_bytes()
        return f'0x{self.value_object.hex()}'

    def process_encode(self, value):
        return ScaleBytes(bytes.fromhex(value[2:]))


class U8(ScaleType):

    def process(self):
        return self.get_next_u8()

    def process_encode(self, value):

        if 0 <= int(value) <= 2**8 - 1:
            return ScaleBytes(bytearray(int(value).to_bytes(1, 'little')))
        else:
            raise ValueError('{} out of range for u8'.format(value))


class U16(ScaleType):

    def process(self):
        return int.from_bytes(self.get_next_bytes(2), byteorder='little')

    def process_encode(self, value):

        if 0 <= int(value) <= 2**16 - 1:
            return ScaleBytes(bytearray(int(value).to_bytes(2, 'little')))
        else:
            raise ValueError('{} out of range for u16'.format(value))


class U32(ScaleType):

    def process(self):
        return int.from_bytes(self.get_next_bytes(4), byteorder='little')

    def process_encode(self, value):

        if 0 <= int(value) <= 2**32 - 1:
            return ScaleBytes(bytearray(int(value).to_bytes(4, 'little')))
        else:
            raise ValueError('{} out of range for u32'.format(value))


class U64(ScaleType):

    def process(self):
        return int(int.from_bytes(self.get_next_bytes(8), byteorder='little'))

    def process_encode(self, value):

        if 0 <= int(value) <= 2**64 - 1:
            return ScaleBytes(bytearray(int(value).to_bytes(8, 'little')))
        else:
            raise ValueError('{} out of range for u64'.format(value))


class U128(ScaleType):

    def process(self):
        return int(int.from_bytes(self.get_next_bytes(16), byteorder='little'))

    def process_encode(self, value):

        if 0 <= int(value) <= 2**128 - 1:
            return ScaleBytes(bytearray(int(value).to_bytes(16, 'little')))
        else:
            raise ValueError('{} out of range for u128'.format(value))


class U256(ScaleType):

    def process(self):
        return int(int.from_bytes(self.get_next_bytes(32), byteorder='little'))

    def process_encode(self, value):

        if 0 <= int(value) <= 2**256 - 1:
            return ScaleBytes(bytearray(int(value).to_bytes(32, 'little')))
        else:
            raise ValueError('{} out of range for u256'.format(value))


class I8(ScaleType):

    def process(self):
        return int.from_bytes(self.get_next_bytes(1), byteorder='little', signed=True)

    def process_encode(self, value):

        if -128 <= int(value) <= 127:
            return ScaleBytes(bytearray(int(value).to_bytes(1, 'little', signed=True)))
        else:
            raise ValueError('{} out of range for i8'.format(value))


class I16(ScaleType):

    def process(self):
        return int.from_bytes(self.get_next_bytes(2), byteorder='little', signed=True)

    def process_encode(self, value):

        if -32768 <= int(value) <= 32767:
            return ScaleBytes(bytearray(int(value).to_bytes(2, 'little', signed=True)))
        else:
            raise ValueError('{} out of range for i16'.format(value))


class I32(ScaleType):

    def process(self):
        return int.from_bytes(self.get_next_bytes(4), byteorder='little', signed=True)

    def process_encode(self, value):

        if -2147483648 <= int(value) <= 2147483647:
            return ScaleBytes(bytearray(int(value).to_bytes(4, 'little', signed=True)))
        else:
            raise ValueError('{} out of range for i32'.format(value))


class I64(ScaleType):

    def process(self):
        return int.from_bytes(self.get_next_bytes(8), byteorder='little', signed=True)

    def process_encode(self, value):

        if -2**64 <= int(value) <= 2**64-1:
            return ScaleBytes(bytearray(int(value).to_bytes(8, 'little', signed=True)))
        else:
            raise ValueError('{} out of range for i64'.format(value))


class I128(ScaleType):

    def process(self):
        return int.from_bytes(self.get_next_bytes(16), byteorder='little', signed=True)

    def process_encode(self, value):

        if -2**128 <= int(value) <= 2**128-1:
            return ScaleBytes(bytearray(int(value).to_bytes(16, 'little', signed=True)))
        else:
            raise ValueError('{} out of range for i128'.format(value))


class I256(ScaleType):

    def process(self):
        return int.from_bytes(self.get_next_bytes(32), byteorder='little', signed=True)

    def process_encode(self, value):

        if -2**256 <= int(value) <= 2**256-1:
            return ScaleBytes(bytearray(int(value).to_bytes(32, 'little', signed=True)))
        else:
            raise ValueError('{} out of range for i256'.format(value))


class H160(ScaleType):

    def process(self):
        return '0x{}'.format(self.get_next_bytes(20).hex())

    def process_encode(self, value):
        if value[0:2] != '0x' or len(value) != 42:
            raise ValueError('Value should start with "0x" and should be 20 bytes long')
        return ScaleBytes(value)


class H256(ScaleType):

    def process(self):
        return '0x{}'.format(self.get_next_bytes(32).hex())

    def process_encode(self, value):
        if value[0:2] != '0x' or len(value) != 66:
            raise ValueError('Value should start with "0x" and should be 32 bytes long')
        return ScaleBytes(value)


class H512(ScaleType):

    def process(self):
        return '0x{}'.format(self.get_next_bytes(64).hex())

    def process_encode(self, value: Union[str, bytes]):

        if type(value) is bytes and len(value) != 64:
            raise ValueError('Value should be 64 bytes long')

        if type(value) is str and (value[0:2] != '0x' or len(value) != 130):
            raise ValueError('Value should start with "0x" and should be 64 bytes long')

        return ScaleBytes(value)


class Struct(ScaleType):

    def __init__(self, data=None, type_mapping=None, **kwargs):

        if type_mapping:
            self.type_mapping = type_mapping

        super().__init__(data, **kwargs)

    def process(self):

        result = {}
        self.value_object = {}

        for key, data_type in self.type_mapping:
            if data_type is None:
                data_type = 'Null'
            field_obj = self.process_type(data_type, metadata=self.metadata)

            self.value_object[key] = field_obj

            result[key] = field_obj.value

        return result

    def process_encode(self, value):
        data = ScaleBytes(bytearray())

        self.value_object = {}

        for key, data_type in self.type_mapping:
            if key not in value:
                raise ValueError('Element "{}" of struct is missing in given value'.format(key))

            element_obj = self.runtime_config.create_scale_object(
                type_string=data_type, metadata=self.metadata
            )
            data += element_obj.encode(value[key])
            self.value_object[key] = element_obj

        return data


class Tuple(ScaleType):
    def __init__(self, data=None, type_mapping=None, **kwargs):

        if type_mapping:
            self.type_mapping = type_mapping

        super().__init__(data, **kwargs)

    def process(self):

        if len(self.type_mapping) == 1:
            return self.process_type(self.type_mapping[0], metadata=self.metadata).value

        result = ()
        self.value_object = ()

        for member_type in self.type_mapping:
            if member_type is None:
                member_type = 'Null'

            member_obj = self.process_type(member_type, metadata=self.metadata)

            result += (member_obj.value,)
            self.value_object += (member_obj,)

        return result

    def process_encode(self, value):
        data = ScaleBytes(bytearray())
        self.value_object = ()

        if type(value) not in (list,  tuple):
            value = [value]

        if len(value) != len(self.type_mapping):
            raise ValueError('Element count of value ({}) doesn\'t match type_definition ({})'.format(
                len(value), len(self.type_mapping))
            )

        for idx, member_type in enumerate(self.type_mapping):

            element_obj = self.runtime_config.create_scale_object(
                member_type, metadata=self.metadata
            )
            data += element_obj.encode(value[idx])
            self.value_object += (element_obj,)

        return data


class Set(ScaleType):
    value_list = []
    value_type = 'u64'

    def __init__(self, data, value_list=None, **kwargs):
        self.set_value = None

        if value_list:
            self.value_list = value_list

        super().__init__(data, **kwargs)

    def process(self):
        self.set_value = self.process_type(self.value_type).value
        result = []
        if self.set_value > 0:

            for value, set_mask in self.value_list.items():
                if self.set_value & set_mask > 0:
                    result.append(value)
        return result

    def process_encode(self, value):
        result = 0
        if type(value) is not list:
            raise ValueError('Value for encoding a set must be a list')

        for item, set_mask in self.value_list.items():
            if item in value:
                result += set_mask

        u64_obj = self.runtime_config.create_scale_object(type_string=self.value_type)

        return u64_obj.encode(result)


class Era(ScaleType):
    """
    An Era represents a range of blocks in which a transaction is allowed to be
    executed.

    An Era may either be "immortal", in which case the transaction is always valid,
    or "mortal", in which case the transaction has a defined start block and period
    in which it is valid.
    """

    def __init__(self, **kwargs):
        self.period = None
        self.phase = None
        super().__init__(**kwargs)

    def process(self):

        option_byte = self.get_next_bytes(1).hex()
        if option_byte == '00':
            self.period = None
            self.phase = None
            return option_byte
        else:
            encoded = int(option_byte, base=16) + (int(self.get_next_bytes(1).hex(), base=16) << 8)
            self.period = 2 << (encoded % (1 << 4))
            quantize_factor = max(1, (self.period >> 12))
            self.phase = (encoded >> 4) * quantize_factor
            if self.period >= 4 and self.phase < self.period:
                return (self.period, self.phase)
            else:
                raise ValueError('Invalid phase and period: {}, {}'.format(self.phase, self.period))

    def _tuple_from_dict(self, value):
        if 'period' not in value:
            raise ValueError("Value missing required field 'period' in dict Era")
        period = value['period']

        if 'phase' in value:
            return (period, value['phase'])

        # If phase not specified explicitly, let the user specify the current block,
        # and calculate the phase from that.
        if 'current' not in value:
            raise ValueError("Dict Era must have one of the fields 'phase' or 'current'")

        current = value['current']

        # Period must be a power of two between 4 and 2**16
        period = max(4, min(1 << 16, next_power_of_two(period)))
        phase = current % period
        quantize_factor = max(1, (period >> 12))
        quantized_phase = (phase // quantize_factor) * quantize_factor

        return (period, quantized_phase)

    def process_encode(self, value):
        if value == '00':
            self.period = None
            self.phase = None
            return ScaleBytes('0x00')
        if isinstance(value, dict):
            value = self._tuple_from_dict(value)
        if isinstance(value, tuple) and len(value) == 2:
            period, phase = value
            if not isinstance(phase, int) or not isinstance(period, int):
                raise ValueError("Phase and period must be ints")
            if phase > period:
                raise ValueError("Phase must be less than period")
            self.period = period
            self.phase = phase
            quantize_factor = max(period >> 12, 1)
            encoded = min(15, max(1, trailing_zeros(period) - 1)) | ((phase // quantize_factor) << 4)
            return ScaleBytes(encoded.to_bytes(length=2, byteorder='little', signed=False))

        raise ValueError("Value must be the string '00' or tuple of two ints")

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

    @classmethod
    def process_scale_info_definition(cls, scale_info_definition: 'GenericRegistryType', prefix: str):
        return


class Bool(ScaleType):

    def process(self):
        return self.get_next_bool()

    def process_encode(self, value):
        if value is True:
            return ScaleBytes('0x01')
        elif value is False:
            return ScaleBytes('0x00')
        else:
            raise ValueError("Value must be boolean")


class CompactMoment(CompactU32):
    type_string = 'Compact<Moment>'

    def to_datetime(self):
        return datetime.utcfromtimestamp(self.value)


class ProposalPreimage(Struct):
    type_string = '(Vec<u8>, AccountId, BalanceOf, BlockNumber)'

    type_mapping = (
        ("proposal", "HexBytes"),
        ("registredBy", "AccountId"),
        ("deposit", "BalanceOf"),
        ("blockNumber", "BlockNumber")
    )

    def process(self):

        result = {}
        for key, data_type in self.type_mapping:
            result[key] = self.process_type(data_type, metadata=self.metadata).value

        # Replace HexBytes with actual proposal
        result['proposal'] = self.runtime_config.create_scale_object(
            'Proposal', data=ScaleBytes(result['proposal']), metadata=self.metadata
        ).decode()

        return result


class GenericAccountId(H256):

    def __init__(self, data=None, **kwargs):
        self.ss58_address = None
        self.public_key = None
        super().__init__(data, **kwargs)

    def process_encode(self, value):
        if value[0:2] != '0x':
            from scalecodec.utils.ss58 import ss58_decode
            self.ss58_address = value
            value = '0x{}'.format(ss58_decode(value))
        return super().process_encode(value)

    def serialize(self):
        return self.ss58_address or self.value

    def process(self):
        value = self.public_key = super().process()

        if self.runtime_config.ss58_format is not None:
            try:
                value = self.ss58_address = ss58_encode(value, ss58_format=self.runtime_config.ss58_format)
            except ValueError:
                pass

        return value

    @classmethod
    def process_scale_info_definition(cls, scale_info_definition: 'GenericRegistryType', prefix: str):
        return


class GenericEthereumAccountId(H160):

    @classmethod
    def process_scale_info_definition(cls, scale_info_definition: 'GenericRegistryType', prefix: str):
        return


class GenericAccountIndex(U32):
    pass


class Vec(ScaleType):

    def __init__(self, data=None, **kwargs):
        self.elements = []
        super().__init__(data, **kwargs)

    def process(self):
        element_count = self.process_type('Compact<u32>').value

        # Check for Bytes processing
        if self.runtime_config.get_decoder_class(self.sub_type) is U8:
            self.value_object = self.get_next_bytes(element_count)

            try:
                return self.value_object.decode()
            except UnicodeDecodeError:
                return '0x{}'.format(self.value_object.hex())

        result = []
        for _ in range(0, element_count):
            element = self.process_type(self.sub_type, metadata=self.metadata)
            self.elements.append(element)
            result.append(element.value)

        self.value_object = self.elements

        return result

    def process_encode(self, value):

        # encode element count to Compact<u32>
        element_count_compact = CompactU32()

        # Check for Bytes processing
        if self.runtime_config.get_decoder_class(self.sub_type) is U8:
            string_length_compact = CompactU32()

            if type(value) is str:
                if value[0:2] == '0x':
                    # TODO implicit HexBytes conversion can have unexpected result if string is actually starting with '0x'
                    value = bytes.fromhex(value[2:])
                else:
                    value = value.encode()

            elif type(value) in (bytearray, list):
                value = bytes(value)

            if type(value) is not bytes:
                raise ValueError(f'Cannot encode type "{type(value)}"')

            self.value_object = value

            data = string_length_compact.encode(len(value))
            data += value

            return data

        if type(value) is not list:
            raise ValueError("Provided value is not a list")

        element_count_compact.encode(len(value))

        data = element_count_compact.data
        self.value_object = []

        for element in value:

            element_obj = self.runtime_config.create_scale_object(
                type_string=self.sub_type, metadata=self.metadata
            )
            data += element_obj.encode(element)
            self.value_object.append(element_obj)

        return data

    def __len__(self):
        return len(self.value_object)


class BoundedVec(Vec):
    def __init__(self, data=None, **kwargs):

        if self.sub_type and ',' in self.sub_type:
            # Rebuild sub_type as last item is the upper bound of elements allowed
            self.sub_type, self.max_elements = [x.strip() for x in self.sub_type.rsplit(',', 1)]

        super().__init__(data, **kwargs)

    @classmethod
    def process_scale_info_definition(cls, scale_info_definition: 'GenericRegistryType', prefix: str):
        cls.sub_type = f"{prefix}::{scale_info_definition.value['params'][0]['type']}"


class BitVec(ScaleType):
    """
    A BitVec that represents an array of bits. The bits are however stored encoded. The difference between this
    and a normal Bytes would be that the length prefix indicates the number of bits encoded, not the bytes
    """
    def process(self):
        length_obj = self.process_type('Compact<u32>')

        total = math.ceil(length_obj.value / 8)

        value_int = int.from_bytes(self.get_next_bytes(total), byteorder='little')

        return '0b' + bin(value_int)[2:].zfill(length_obj.value)

    def process_encode(self, value):

        if type(value) is list:
            value = sum(v << i for i, v in enumerate(reversed(value)))

        if type(value) is str and value[0:2] == '0b':
            value = int(value[2:], 2)

        if type(value) is not int:
            raise ValueError("Provided value is not an int, binary str or a list of booleans")

        self.value_object = value

        if value == 0:
            return ScaleBytes(b'\x00')

        # encode the length in a compact u32
        compact_obj = CompactU32()
        data = compact_obj.encode(value.bit_length())

        byte_length = math.ceil(value.bit_length() / 8)

        return data + value.to_bytes(length=byte_length, byteorder='little')


class GenericAddress(ScaleType):

    def __init__(self, data=None, **kwargs):
        self.account_length = None
        self.account_id = None
        self.account_index = None
        self.account_idx = None
        super().__init__(data, **kwargs)

    def process(self):
        self.account_length = self.get_next_bytes(1)

        if self.account_length == b'\xff':
            self.account_id = self.get_next_bytes(32).hex()
            self.account_length = self.account_length.hex()

            return self.account_id
        else:
            if self.account_length == b'\xfc':
                account_index = self.get_next_bytes(2)
            elif self.account_length == b'\xfd':
                account_index = self.get_next_bytes(4)
            elif self.account_length == b'\xfe':
                account_index = self.get_next_bytes(8)
            else:
                account_index = self.account_length

            self.account_index = account_index.hex()
            self.account_idx = int.from_bytes(account_index, byteorder='little')

            self.account_length = self.account_length.hex()

            return self.account_index

    def process_encode(self, value):

        if type(value) == str and value[0:2] != '0x':
            # Assume SS58 encoding address
            if len(value) >= 46:
                from scalecodec.utils.ss58 import ss58_decode
                value = '0x{}'.format(ss58_decode(value))
            else:
                from scalecodec.utils.ss58 import ss58_decode_account_index
                index_obj = GenericAccountIndex()
                value = index_obj.encode(ss58_decode_account_index(value))

        if type(value) == str and value[0:2] == '0x' and len(value) == 66:
            # value is AccountId
            return ScaleBytes('0xff{}'.format(value[2:]))
        elif type(value) == int:
            # value is AccountIndex
            raise NotImplementedError('Encoding of AccountIndex Adresses not supported yet')
        else:
            raise ValueError('Value is in unsupported format, expected 32 bytes hex-string for AccountIds or int for AccountIndex')

    def serialize(self):
        if self.account_id:
            return '0x{}'.format(self.value)
        else:
            return self.value


class AccountIdAddress(GenericAddress):

    def process(self):
        self.account_id = self.process_type('AccountId').value.replace('0x', '')
        self.account_length = 'ff'
        return self.account_id

    def process_encode(self, value):
        if type(value) == str and value[0:2] != '0x':
            # Assume SS58 encoding address
            if len(value) >= 46:
                from scalecodec.utils.ss58 import ss58_decode
                value = '0x{}'.format(ss58_decode(value))
            else:
                from scalecodec.utils.ss58 import ss58_decode_account_index
                index_obj = GenericAccountIndex()
                value = index_obj.encode(ss58_decode_account_index(value))

        if type(value) == str and value[0:2] == '0x' and len(value) == 66:
            # value is AccountId
            return ScaleBytes('0x{}'.format(value[2:]))
        elif type(value) == int:
            # value is AccountIndex
            raise NotImplementedError('Encoding of AccountIndex Adresses not supported yet')
        else:
            raise ValueError('Value is in unsupported format, expected 32 bytes hex-string for AccountIds or int for AccountIndex')


class RawAddress(GenericAddress):
    pass


class Enum(ScaleType):

    value_list = []
    type_mapping = None

    def __init__(self, data=None, value_list=None, type_mapping=None, **kwargs):

        self.index = None

        if type_mapping:
            self.type_mapping = type_mapping

        if value_list:
            self.value_list = value_list

        super().__init__(data, **kwargs)

    def process(self):
        self.index = int(self.get_next_bytes(1).hex(), 16)

        if self.type_mapping:
            try:
                enum_type_mapping = self.type_mapping[self.index]

                if enum_type_mapping[1] is None or enum_type_mapping[1] == 'Null':
                    self.value_object = (enum_type_mapping[0], None)
                    return enum_type_mapping[0]

                result_obj = self.process_type(enum_type_mapping[1], metadata=self.metadata)

                self.value_object = (enum_type_mapping[0], result_obj)

                return {enum_type_mapping[0]: result_obj.value}

            except IndexError:
                raise ValueError("Index '{}' not present in Enum type mapping".format(self.index))
        else:
            try:
                return self.value_list[self.index]
            except IndexError:
                raise ValueError("Index '{}' not present in Enum value list".format(self.index))

    def process_encode(self, value):
        if self.type_mapping:

            if type(value) == str:
                # Convert simple enum values
                value = {value: None}

            if type(value) != dict:
                raise ValueError("Value must be a dict or str when type_mapping is set, not '{}'".format(value))

            if len(value) != 1:
                raise ValueError("Value for enum with type_mapping can only have one value")

            for enum_key, enum_value in value.items():
                for idx, (item_key, item_value) in enumerate(self.type_mapping):
                    if item_key == enum_key:
                        self.index = idx
                        struct_obj = self.runtime_config.create_scale_object(
                            type_string='Struct',
                            type_mapping=[(item_key, item_value)]
                        )
                        struct_data = struct_obj.encode(value)
                        self.value_object = (item_key, struct_obj)
                        return ScaleBytes(bytearray([self.index])) + struct_data

                raise ValueError("Value '{}' not present in type_mapping of this enum".format(enum_key))

        else:

            if type(self.value_list) is dict:
                value_list = self.value_list.items()
            else:
                value_list = enumerate(self.value_list)

            for idx, item in value_list:
                if item == value:
                    self.index = idx
                    return ScaleBytes(bytearray([self.index]))

            raise ValueError("Value '{}' not present in value list of this enum".format(value))

    def get_enum_value(self):
        if self.value:

            if self.type_mapping:

                if self.type_mapping[self.index][1] == 'Null':
                    return self.value

                return list(self.value.values())[0]
            else:
                return self.value_list[self.index]


class Data(Enum):
    type_mapping = [
        ["None", "Null"],
        ["Raw", "Bytes"],
        ["BlakeTwo256", "H256"],
        ["Sha256", "H256"],
        ["Keccak256", "H256"],
        ["ShaThree256", "H256"]
      ]

    def process(self):

        self.index = int(self.get_next_bytes(1).hex(), 16)

        if self.index == 0:
            return {'None': None}

        elif 1 <= self.index <= 33:
            # Determine value of Raw type (length is processed in index byte)
            data = self.get_next_bytes(self.index - 1)

            try:
                value = data.decode()
            except UnicodeDecodeError:
                value = '0x{}'.format(data.hex())
            return {"Raw": value}

        elif 34 <= self.index <= 37:

            enum_value = self.type_mapping[self.index - 32][0]

            return {enum_value: self.process_type(self.type_mapping[self.index - 32][1]).value}

        raise ValueError("Unable to decode Data, invalid indicator byte '{}'".format(self.index))

    def process_encode(self, value):

        if type(value) != dict:
            raise ValueError("Value must be a dict when type_mapping is set, not '{}'".format(value))

        if len(value) != 1:
            raise ValueError("Value for enum with type_mapping can only have one value")

        for enum_key, enum_value in value.items():

            for idx, (item_key, item_value) in enumerate(self.type_mapping):
                if item_key == enum_key:
                    self.index = idx

                    if item_value == 'Null':
                        return ScaleBytes(bytearray([0]))

                    elif item_value == 'Bytes':

                        if enum_value[0:2] == '0x':

                            if len(enum_value) > 66:
                                raise ValueError("Raw type in Data cannot exceed 32 bytes")

                            enum_value = bytes.fromhex(enum_value[2:])
                            data = bytes([len(enum_value) + 1]) + enum_value
                            return ScaleBytes(bytearray(data))
                        else:

                            if len(enum_value) > 32:
                                raise ValueError("Raw type in Data cannot exceed 32 bytes")

                            data = bytes([len(enum_value) + 1]) + enum_value.encode()
                            return ScaleBytes(bytearray(data))
                    else:

                        struct_obj = self.runtime_config.create_scale_object(
                            type_string=self.type_mapping[self.index][1]
                        )
                        return ScaleBytes(bytearray([self.index + 32])) + struct_obj.encode(enum_value)

            raise ValueError("Value '{}' not present in type_mapping of this enum".format(enum_key))

    @classmethod
    def process_scale_info_definition(cls, scale_info_definition: 'GenericRegistryType', prefix: str):
        return


class Null(ScaleType):

    def process(self):
        return None

    def process_encode(self, value):
        return ScaleBytes(bytearray())


class StorageHasher(Enum):

    value_list = ['Blake2_128', 'Blake2_256', 'Blake2_128Concat', 'Twox128', 'Twox256', 'Twox64Concat', 'Identity']

    def is_blake2_128(self):
        return self.index == 0

    def is_blake2_256(self):
        return self.index == 1

    def is_twoblake2_128_concat(self):
        return self.index == 2

    def is_twox128(self):
        return self.index == 3

    def is_twox256(self):
        return self.index == 4

    def is_twox64_concat(self):
        return self.index == 5

    def is_identity(self):
        return self.index == 6


class Conviction(Enum):
    CONVICTION_MASK = 0b01111111
    DEFAULT_CONVICTION = 0b00000000

    value_list = ['None', 'Locked1x', 'Locked2x', 'Locked3x', 'Locked4x', 'Locked5x', 'Locked6x']


class GenericBlock(ScaleType):
    # TODO implement generic block type

    def process(self):
        raise NotImplementedError()

    def process_encode(self, value):
        raise NotImplementedError()


class GenericVote(U8):

    def process(self):
        value = super().process()

        conviction = self.runtime_config.create_scale_object(
            'Conviction',
        )

        conviction.decode(ScaleBytes(bytearray([value & Conviction.CONVICTION_MASK])))

        aye = (value & 0b1000_0000) == 0b1000_0000

        self.value_object = {
            'aye': aye,
            'conviction': conviction
        }

        return {
            'aye': aye,
            'conviction': conviction.value
        }

    def process_encode(self, value):

        if type(value) is dict:
            conviction = self.runtime_config.create_scale_object('Conviction')
            conviction.encode(value['conviction'])

            value = conviction.index | (0b1000_0000 if value['aye'] else 0)

        if type(value) is not int:
            raise ValueError('Incorrect format for vote')

        return super().process_encode(value)


class GenericCall(ScaleType):

    def __init__(self, data, **kwargs):
        self.call_index = None
        self.call_function = None
        self.call_args = {}
        self.call_module = None
        self.call_hash = None

        super().__init__(data, **kwargs)

    def process(self):

        if self.metadata.portable_registry:
            pallet_index = self.process_type('U8')

            self.call_module = self.metadata.get_pallet_by_index(pallet_index.value)
            call_type_string = self.call_module['calls'].value_object.get_type_string()

            call_obj = self.process_type(call_type_string, metadata=self.metadata)

            self.call_index = "{:02x}{:02x}".format(pallet_index.value, call_obj.index)

            self.call_function = call_obj.scale_info_type['def'][1].get_variant_by_index(call_obj.index)

            self.call_args = self.call_function['fields']

            call_hash = blake2b(self.get_used_bytes(), digest_size=32).digest()

            call_args = []

            if len(self.call_args) > 0:

                # Check args format
                if type(call_obj[1].value) is not tuple:
                    call_args_values = (call_obj[1],)
                else:
                    call_args_values = call_obj[1]

                for idx, call_arg in enumerate(self.call_args):
                    call_args.append({
                        'name': call_arg.value['name'],
                        'type': self.convert_type(call_arg.value['typeName']),
                        'value': call_args_values[idx].value
                    })
                    self.call_args[idx].value_object['value'] = call_args_values[idx]

            self.value_object = {
                'call_index': f'0x{self.call_index}',
                'call_function': self.call_function,
                'call_module': self.call_module,
                'call_args': self.call_args,
                'call_hash': f'0x{call_hash.hex()}'
            }

            return {
                'call_index': f'0x{self.call_index}',
                'call_function': self.call_function.name,
                'call_module': self.call_module.name,
                'call_args': call_args,
                'call_hash': f'0x{call_hash.hex()}'
            }

        else:

            self.call_index = self.get_next_bytes(2).hex()

            self.call_module, self.call_function = self.metadata.call_index[self.call_index]

            call_bytes = bytes.fromhex(self.call_index)

            call_args_serialized = []

            for arg in self.call_function.args:
                arg_type_obj = self.process_type(arg.type, metadata=self.metadata)

                call_bytes += arg_type_obj.get_used_bytes()

                self.call_args[arg.name] = arg_type_obj

                call_args_serialized.append({
                    'name': arg.name,
                    'type': arg.type,
                    'value': arg_type_obj.serialize()
                })

            call_hash = blake2b(call_bytes, digest_size=32).digest()

            self.value_object = {
                'call_index': f'0x{self.call_index}',
                'call_function': self.call_function,
                'call_module': self.call_module,
                'call_args': self.call_args,
                'call_hash': f'0x{call_hash.hex()}'
            }

            return {
                'call_index': f'0x{self.call_index}',
                'call_function': self.call_function.name,
                'call_module': self.call_module.name,
                'call_args': call_args_serialized,
                'call_hash': f'0x{call_hash.hex()}'
            }

    def process_encode(self, value):

        self.value_object = {}

        if type(value) is not dict:
            raise TypeError("value must be of type dict to encode a GenericCall")

        if self.metadata.portable_registry:
            if 'call_index' in value:
                raise NotImplementedError()
            elif 'call_module' in value and 'call_function' in value:
                self.call_module = self.metadata.get_metadata_pallet(value['call_module'])
                self.value_object['call_module'] = self.call_module

            elif not self.call_module or not self.call_function:
                raise ValueError('No call module and function specified')

            if not self.call_module:
                raise ValueError(f"Pallet '{value['call_module']}' not found")

            data = ScaleBytes(self.call_module['index'].get_used_bytes())

            call_type_string = self.call_module['calls'].value_object.get_type_string()

            call_obj = self.runtime_config.create_scale_object(call_type_string)

            # Retrieve used variant of call type
            self.call_function = call_obj.scale_info_type['def'][1].get_variant_by_name(value['call_function'])

            if not self.call_function:
                raise ValueError(f"Call function '{value['call_module']}.{value['call_function']}' not found")

            self.value_object['call_function'] = self.call_function

            data += ScaleBytes(self.call_function['index'].get_used_bytes())

            self.call_index = "{:02x}{:02x}".format(
                self.call_module.value['index'], self.call_function.value['index']
            )

            self.call_args = self.call_function['fields']

            # Encode call params
            if len(self.call_args) > 0:
                self.value_object['call_args'] = {}

                for arg in self.call_args:
                    if arg.value['name'] not in value['call_args']:
                        raise ValueError('Parameter \'{}\' not specified'.format(arg.value['name']))
                    else:
                        param_value = value['call_args'][arg.value['name']]

                        arg_obj = self.runtime_config.create_scale_object(
                            type_string=arg.get_type_string(),
                            metadata=self.metadata
                        )
                        data += arg_obj.encode(param_value)

                        self.value_object['call_args'][arg.value['name']] = arg_obj

            self.call_hash = blake2b(data.data, digest_size=32).digest()

            return data

        else:

            # Check requirements
            if 'call_index' in value:
                self.call_index = self.value_object['call_index'] = value['call_index']

            elif 'call_module' in value and 'call_function' in value:
                # Look up call module from metadata
                for call_index, (call_module, call_function) in self.metadata.call_index.items():

                    if call_module.name == value['call_module'] and call_function.name == value['call_function']:
                        self.call_index = self.value_object['call_index'] = call_index
                        self.call_module = self.value_object['call_module'] = call_module
                        self.call_function = self.value_object['call_function'] = call_function
                        break

                if not self.call_index:
                    raise MetadataCallFunctionNotFound(
                        f"Call function '{value['call_module']}.{value['call_function']}' not found in metadata"
                    )

            elif not self.call_module or not self.call_function:
                raise ValueError('No call module and function specified')

            data = ScaleBytes(bytearray.fromhex(self.call_index))

            # Encode call params
            if len(self.call_function.args) > 0:
                self.value_object['call_args'] = {}

                for arg in self.call_function.args:
                    if arg.name not in value['call_args']:
                        raise ValueError('Parameter \'{}\' not specified'.format(arg.name))
                    else:
                        param_value = value['call_args'][arg.name]

                        arg_obj = self.runtime_config.create_scale_object(
                            type_string=arg.type, metadata=self.metadata
                        )
                        data += arg_obj.encode(param_value)

                        self.value_object['call_args'][arg.name] = arg_obj

            return data


class GenericContractExecResult(Enum):
    def __init__(self, data=None, contract_result_scale_type=None, **kwargs):
        self.contract_result_scale_type = contract_result_scale_type
        self.gas_consumed = None
        self.gas_required = None
        self.flags = None
        self.contract_result_data = None
        super().__init__(data, **kwargs)

    def process(self):
        value = super().process()
        self.process_contract_result()
        return value

    def process_contract_result(self):
        if 'success' in self.value:
            self.gas_consumed = self.value['success']['gas_consumed']
            self.gas_required = self.value['success']['gas_required']
            self.flags = self.value['success']['flags']
            self.contract_result_data = self.value['success']['data']

    def process_encode(self, value):

        if self.contract_result_scale_type is None:
            raise ValueError("Encoding is not possible because 'contract_result_scale_type' is not set")

        if 'success' in value:
            value = {'Success': value['success']}
        return super().process_encode(value)


class OpaqueCall(Bytes):

    def process_encode(self, value):
        call_obj = self.runtime_config.create_scale_object(
            type_string='Call', metadata=self.metadata
        )
        return super().process_encode(str(call_obj.encode(value)))

    def process(self):
        value = super().process()
        try:
            call_obj = self.runtime_config.create_scale_object(
                type_string='Call',
                data=ScaleBytes(value),
                metadata=self.metadata
            )

            return call_obj.process()
        except:
            return value


class WrapperKeepOpaque(Struct):

    def process_encode(self, value):
        # Check requirements
        if not self.type_mapping or len(self.type_mapping) != 2:
            raise ValueError("type_mapping not set correctly for this WrapperKeepOpaque")

        wrapped_obj = self.runtime_config.create_scale_object(
            type_string=self.type_mapping[1], metadata=self.metadata
        )

        wrapped_obj.encode(value)

        bytes_obj = self.runtime_config.create_scale_object("Bytes")
        return bytes_obj.encode(wrapped_obj.get_used_bytes())

    def process(self):
        # Check requirements
        if not self.type_mapping or len(self.type_mapping) != 2:
            raise ValueError("type_mapping not set correctly for this WrapperKeepOpaque")

        # Get bytes
        bytes_obj = self.process_type("Bytes")
        try:
            # Try to decode bytes with wrapped SCALE type
            wrapped_obj = self.runtime_config.create_scale_object(
                type_string=self.type_mapping[1],
                data=ScaleBytes(bytes_obj.value_object),
                metadata=self.metadata
            )

            return wrapped_obj.process()
        except:
            # Decoding failed; return Opaque type
            self.value_object = bytes_obj.value_object
            return f'0x{bytes_obj.value_object.hex()}'


class MultiAccountId(GenericAccountId):

    @classmethod
    def create_from_account_list(cls, accounts, threshold):
        from scalecodec.utils.ss58 import ss58_decode

        account_ids = []
        for account in accounts:
            if account[0:2] != '0x':
                account = '0x{}'.format(ss58_decode(account))
            account_ids.append(account)

        account_list_cls = cls.runtime_config.create_scale_object('Vec<AccountId>')
        account_list_data = account_list_cls.encode(sorted(account_ids))
        threshold_data = cls.runtime_config.create_scale_object("u16").encode(threshold)

        multi_account_id = "0x{}".format(blake2b(
            b"modlpy/utilisuba" + bytes(account_list_data.data) + bytes(threshold_data.data), digest_size=32
        ).digest().hex())

        multi_account_obj = cls(runtime_config=cls.runtime_config)
        multi_account_obj.encode(multi_account_id)

        return multi_account_obj


class FixedLengthArray(ScaleType):

    element_count = 0

    def process(self):

        if self.element_count:
            if self.runtime_config.get_decoder_class(self.sub_type) is U8:
                self.value_object = self.get_next_bytes(self.element_count)
                return '0x{}'.format(self.value_object.hex())
            else:
                result = []
                for idx in range(self.element_count):
                    result.append(self.process_type(self.sub_type).value)
        else:
            result = []

        return result

    def process_encode(self, value):
        data = ScaleBytes(bytearray())

        value = value or []

        if self.runtime_config.get_decoder_class(self.sub_type) is U8:
            # u8 arrays are represented as hex-bytes (e.g. [u8; 3] as 0x123456)
            if value[0:2] != '0x' or len(value[2:]) != self.element_count * 2:
                raise ValueError('Value should start with "0x" and should be {} bytes long'.format(self.element_count))

            return ScaleBytes(value)

        else:

            if not type(value) is list:
                raise ValueError('Given value is not a list')

            for element_value in value:
                element_obj = self.runtime_config.create_scale_object(
                    type_string=self.sub_type, metadata=self.metadata
                )
                data += element_obj.encode(element_value)

            return data


class GenericMultiAddress(Enum):
    type_mapping = [
        ["Id", "AccountId"],
        ["Index", "Compact<AccountIndex>"],
        ["Raw", "HexBytes"],
        ["Address32", "H256"],
        ["Address20", "H160"],
      ]

    def __init__(self, data, **kwargs):
        self.account_length = None
        self.account_id = None
        self.account_index = None
        self.account_idx = None
        super().__init__(data, **kwargs)

    def process(self):
        value = super().process()
        self.account_length = self.index
        if self.index == 0:
            value = list(value.values())[0]

            if is_valid_ss58_address(value):
                self.account_id = ss58_decode(value)
            elif value[0:2] == '0x':
                self.account_id = value[2:]

            return value
        elif self.index == 1:
            self.account_index = list(value.values())[0]
            return self.account_index
        else:
            # Todo cap HexBytes / zero pad to 32 bytes to keep compatibility with AccountId
            account_id = list(value.values())[0]
            self.account_id = account_id[2:66].ljust(64, '0')
            return value

    def process_encode(self, value):

        if type(value) is int:
            # Implied decoded AccountIndex
            value = {"Index": value}

        elif type(value) is str:
            if len(value) <= 8 and value[0:2] != '0x':
                # Implied raw AccountIndex
                self.account_index = ss58_decode_account_index(value)
                value = {"Index": self.account_index}
            elif is_valid_ss58_address(value):
                # Implied SS58 encoded AccountId
                self.account_id = ss58_decode(value)
                value = {"Id": f'0x{self.account_id}'}
            elif len(value) == 66 and value[0:2] == '0x':
                # Implied raw AccountId
                self.account_id = value[2:]
                value = {"Id": value}
            elif len(value) == 42:
                # Implied raw Address20
                value = {"Address20": value}
            else:
                raise NotImplementedError("Address type not yet supported")

        return super().process_encode(value)


class Map(ScaleType):

    def __init__(self, **kwargs):
        super().__init__(**kwargs)

        self.map_key = None
        self.map_value = None

        if self.sub_type:
            sub_type_parts = [x.strip() for x in self.sub_type.split(',')]
            self.map_key = sub_type_parts[0]
            self.map_value = sub_type_parts[1]

    def process(self):

        if self.map_key and self.map_value:

            element_count = self.process_type('Compact<u32>').value

            result = []
            for _ in range(0, element_count):
                key_value = self.process_type(self.map_key, metadata=self.metadata).value
                result.append((key_value, self.process_type(self.map_value, metadata=self.metadata).value))

            return result

        elif self.type_mapping:
            self.value_object = self.process_type(self.type_mapping[0], metadata=self.metadata)
            return self.value_object.value

        else:
            raise ValueError('sub_type or type_mapping should be set to process a Map')

    def process_encode(self, value):

        if type(value) is not list:
            raise ValueError("value should be a list of tuples e.g.: [('1', 2), ('23', 24), ('28', 30), ('45', 80)]")

        element_count_compact = CompactU32()

        element_count_compact.encode(len(value))

        data = element_count_compact.data

        for item_key, item_value in value:
            key_obj = self.runtime_config.create_scale_object(
                type_string=self.map_key, metadata=self.metadata
            )
            data += key_obj.encode(item_key)

            value_obj = self.runtime_config.create_scale_object(
                type_string=self.map_value, metadata=self.metadata
            )
            data += value_obj.encode(item_value)

        return data


class HashMap(Map):
    pass


class BTreeMap(Map):
    pass


class BoundedBTreeMap(BTreeMap):
    pass


class BTreeSet(Vec):
    pass


class GenericMetadataAll(Enum):

    def __init__(self, data, sub_type=None, **kwargs):
        self.__call_index = {}
        self.event_index = {}
        self.error_index = {}

        super().__init__(data, sub_type, **kwargs)

    def get_call_function(self, pallet_index, call_index):
        return self.call_index.get(f'{pallet_index}-{call_index}')

    @property
    def pallets(self):
        metadata_obj = self.value_object[1]

        if self.index >= 14:
            return metadata_obj.value_object['pallets'].value_object
        else:
            return metadata_obj.value_object['modules'].value_object

    @property
    def call_index(self):
        return self.__call_index

    @property
    def portable_registry(self):
        if self.index >= 14:
            return self.value_object[1].value_object['types']

    def get_event(self, pallet_index, event_index):
        pass

    def get_metadata_pallet(self, name: str) -> 'GenericPalletMetadata':

        if self.index >= 14:
            for pallet in self[1]['pallets']:
                if pallet.value['name'] == name:
                    return pallet
        else:
            for pallet in self[1]['modules']:
                if pallet.value['name'] == name:
                    return pallet

    def process(self):
        value = super().process()

        metadata_obj = self.value_object[1]

        if self.index in (12, 13):
            for module in metadata_obj['modules']:

                # Build call index
                if module['calls'].value is not None:
                    for call_index, call in enumerate(module['calls']):
                        call.lookup = "{:02x}{:02x}".format(module["index"].value, call_index)
                        self.call_index[call.lookup] = (module, call)

                # Build event index
                if module['events'].value is not None:
                    for event_index, event in enumerate(module['events']):
                        event.lookup = "{:02x}{:02x}".format(module["index"].value, event_index)
                        self.event_index[event.lookup] = (module, event)

                # Create error index
                if len(module['errors'].value_object or []) > 0:
                    for idx, error in enumerate(module['errors']):
                        self.error_index[f'{module["index"].value_object}-{idx}'] = error

        elif self.index < 12:
            # TODO V9 - V11 processing
            call_module_index = 0
            event_module_index = 0
            error_module_index = 0

            for module in metadata_obj['modules'].value_object:
                # Build call index
                if module['calls'].value_object is not None:
                    for call_index, call in enumerate(module.value_object['calls'].value_object.value_object):
                        call.lookup = "{:02x}{:02x}".format(call_module_index, call_index)
                        self.call_index[call.lookup] = (module, call)
                    call_module_index += 1

                # Build event index
                if module.value_object['events'].value_object is not None:
                    for event_index, event in enumerate(module.value_object['events'].value_object.value_object):
                        event.lookup = "{:02x}{:02x}".format(event_module_index, event_index)
                        self.event_index[event.lookup] = (module, event)
                    event_module_index += 1

                # Create error index
                if len(module.value_object['errors'].value_object or []) > 0:
                    for idx, error in enumerate(module.value_object['errors'].value_object):
                        self.error_index[f'{error_module_index}-{idx}'] = error
                    error_module_index += 1

        return value


class GenericMetadataVersioned(Tuple):

    @property
    def call_index(self):
        return self.value_object[1].call_index

    @property
    def event_index(self):
        return self.value_object[1].event_index

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
    def portable_registry(self):
        return self.value_object[1].portable_registry

    @property
    def pallets(self):
        return self.value_object[1].pallets

    def get_metadata_pallet(self, name: str) -> 'GenericPalletMetadata':
        metadata = self.get_metadata()
        return metadata.get_metadata_pallet(name)

    def get_pallet_by_index(self, index: int):

        for pallet in self.pallets:
            if pallet.value['index'] == index:
                return pallet

        raise ValueError(f'Pallet for index "{index}" not found')

    def get_signed_extensions(self):

        signed_extensions = {}

        if self.portable_registry:
            for se in self.value_object[1][1]['extrinsic']['signed_extensions'].value:
                signed_extensions[se['identifier']] = {
                    'extrinsic': f"scale_info::{se['ty']}",
                    'additional_signed': f"scale_info::{se['additional_signed']}"
                }
        else:
            extension_def = {
                'CheckMortality': {'extrinsic': "Era", 'additional_signed': "Hash"},
                'CheckEra': {'extrinsic': "Era", 'additional_signed': "Hash"},
                'CheckNonce': {'extrinsic': "Compact<Index>", 'additional_signed': None},
                'ChargeTransactionPayment': {'extrinsic': "Compact<Balance>", 'additional_signed': None},
                'CheckSpecVersion': {'extrinsic': None, 'additional_signed': 'u32'},
                'CheckTxVersion': {'extrinsic': None, 'additional_signed': 'u32'},
                'CheckGenesis': {'extrinsic': None, 'additional_signed': 'Hash'},
                'CheckWeight': {'extrinsic': None, 'additional_signed': None},
                'ValidateEquivocationReport': {'extrinsic': None, 'additional_signed': None},
                'LockStakingStatus': {'extrinsic': None, 'additional_signed': None},
                'CheckBlockGasLimit': {'extrinsic': None, 'additional_signed': None},
                'RestrictFunctionality': {'extrinsic': None, 'additional_signed': None},
                'LimitParathreadCommits': {'extrinsic': None, 'additional_signed': None},
                'ChargeAssetTxPayment': {'extrinsic': 'Option<AssetId>', 'additional_signed': None}
            }
            if 'extrinsic' in self.value_object[1][1]:
                for se in self.value_object[1][1]['extrinsic']['signed_extensions'].value:
                    if se not in extension_def:
                        extension_def[se] = {'extrinsic': None, 'additional_signed': None}
                    signed_extensions[se] = extension_def[se]

        return signed_extensions


class GenericStringType(String):
    @property
    def name(self):
        return None

    @property
    def type(self):
        return self.value


class GenericRegistryType(Struct):

    @property
    def docs(self):
        return self.value['docs']

    def process_encode(self, value):
        if 'params' not in value:
            value['params'] = []

        if 'path' not in value:
            value['path'] = []

        if 'docs' not in value:
            value['docs'] = []

        return super().process_encode(value)

    def retrieve_type_decomposition(self):
        return self.value['def']


class GenericField(Struct):

    @property
    def name(self):
        return self.value['name']

    @property
    def docs(self):
        return self.value['docs']

    @property
    def type(self):
        return self.get_type_string()

    def get_type_string(self):
        return f"scale_info::{self.value['type']}"

    def process_encode(self, value):
        if 'name' not in value:
            value['name'] = None

        if 'typeName' not in value:
            value['typeName'] = None

        if 'docs' not in value:
            value['docs'] = []

        return super().process_encode(value)


class GenericVariant(Struct):

    @property
    def args(self):
        return self.value_object['fields']

    @property
    def name(self):
        return self.value['name']

    @property
    def docs(self):
        return self.value['docs']

    def process_encode(self, value):
        if 'index' not in value:
            value['index'] = None

        if 'discriminant' not in value:
            value['discriminant'] = None

        if 'fields' not in value:
            value['fields'] = []

        if 'docs' not in value:
            value['docs'] = []

        return super().process_encode(value)


class GenericTypeDefComposite(Struct):
    def process_encode(self, value):

        if 'fields' not in value:
            value['fields'] = []

        return super().process_encode(value)


class GenericTypeDefVariant(Struct):

    def get_variant_by_name(self, name: str) -> GenericVariant:
        for variant in self.value_object['variants']:
            if variant['name'].value == name:
                return variant

    def get_variant_by_index(self, index: int) -> GenericVariant:
        for variant in self.value_object['variants']:
            if variant['index'].value == index:
                return variant

    def process_encode(self, value):

        if 'variants' not in value:
            value['variants'] = []

        return super().process_encode(value)


class GenericFunctionArgumentMetadata(Struct):

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def process(self):
        value = super().process()
        return value

    @property
    def name(self):
        return self.value['name']

    @property
    def type(self):
        return self.convert_type(self.value['type'])


class GenericFunctionMetadata(Struct):

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    @property
    def name(self):
        return self.value['name']

    def get_identifier(self):
        return self.value['name']

    @property
    def args(self):
        return self.value_object['args'].value_object

    @property
    def docs(self):
        return self.value['documentation']


class ScaleInfoCallMetadata(Struct):

    def get_type_string(self):
        return f"scale_info::{self.value['ty']}"

    @property
    def calls(self):
        if self.value_object:
            call_enum = self.runtime_config.get_decoder_class(
                self.get_type_string()
            )
            return call_enum.scale_info_type['def'][1]['variants']
        else:
            return []


class ScaleInfoPalletErrorMetadata(Struct):
    def get_type_string(self):
        return f"scale_info::{self.value['ty']}"

    @property
    def errors(self):
        if self.value_object:
            error_enum = self.runtime_config.get_decoder_class(self.get_type_string())
            return error_enum.scale_info_type['def'][1]['variants']
        else:
            return []


class ScaleInfoPalletEventMetadata(Struct):
    def get_type_string(self):
        return f"scale_info::{self.value['ty']}"

    @property
    def events(self):
        if self.value_object:
            event_enum = self.runtime_config.get_decoder_class(self.get_type_string())
            return event_enum.scale_info_type['def'][1]['variants']
        else:
            return []


class GenericPalletMetadata(Struct):

    @property
    def name(self):
        return self.value['name']

    def get_identifier(self):
        return self.value['name']

    @property
    def storage(self):
        storage_functions = self.value_object['storage'].value_object

        if storage_functions:
            return storage_functions.value_object['entries'].value_object

    @property
    def calls(self):
        return self.value_object['calls'].value_object

    @property
    def events(self):
        events = self.value_object['events'].value_object

        if events:
            return events.value_object

    @property
    def constants(self):
        return self.value_object['constants'].value_object

    @property
    def errors(self):
        return self.value_object['errors'].value_object

    def get_storage_function(self, name: str):
        storage_functions = self.value_object['storage'].value_object

        if storage_functions.value_object:
            for storage_function in storage_functions['entries']:
                if storage_function.value['name'] == name:
                    return storage_function


class ScaleInfoPalletMetadata(GenericPalletMetadata):

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


class GenericStorageEntryMetadata(Struct):

    @property
    def name(self):
        return self.value['name']

    @property
    def modifier(self):
        return self.value['modifier']

    @property
    def type(self):
        return self.value['type']

    @property
    def docs(self):
        return self.value['documentation']

    def get_type_string_for_type(self, ty):
        return self.convert_type(ty)

    def get_value_type_string(self):
        if 'Plain' in self.value['type']:
            return self.get_type_string_for_type(self.value['type']['Plain'])
        elif 'Map' in self.value['type']:
            return self.get_type_string_for_type(self.value['type']['Map']['value'])
        elif 'DoubleMap' in self.value['type']:
            return self.get_type_string_for_type(self.value['type']['DoubleMap']['value'])
        elif 'NMap' in self.value['type']:
            return self.get_type_string_for_type(self.value['type']['NMap']['value'])
        else:
            raise NotImplementedError()

    def get_params_type_string(self):
        if 'Plain' in self.value['type']:
            return []
        elif 'Map' in self.value['type']:
            return [self.get_type_string_for_type(self.value['type']['Map']['key'])]
        elif 'DoubleMap' in self.value['type']:
            return [
                self.get_type_string_for_type(self.value['type']['DoubleMap']['key1']),
                self.get_type_string_for_type(self.value['type']['DoubleMap']['key2'])
            ]
        elif 'NMap' in self.value['type']:
            return [self.get_type_string_for_type(k) for k in self.value['type']['NMap']['keys']]
        else:
            raise NotImplementedError()

    def get_param_hashers(self):
        if 'Plain' in self.value['type']:
            return ['Twox64Concat']
        elif 'Map' in self.value['type']:
            return [self.value['type']['Map']['hasher']]
        elif 'DoubleMap' in self.value['type']:
            return [
                self.value['type']['DoubleMap']['hasher'],
                self.value['type']['DoubleMap']['key2_hasher']
            ]
        elif 'NMap' in self.value['type']:
            return self.value['type']['NMap']['hashers']
        else:
            raise NotImplementedError()


class ScaleInfoStorageEntryMetadata(GenericStorageEntryMetadata):

    def get_type_string_for_type(self, ty):
        return f'scale_info::{ty}'

    def get_value_type_string(self):
        if 'Plain' in self.value['type']:
            return self.get_type_string_for_type(self.value['type']['Plain'])
        elif 'Map' in self.value['type']:
            return self.get_type_string_for_type(self.value['type']['Map']['value'])
        else:
            raise NotImplementedError()

    def get_key_type_string(self):
        if 'Map' in self.value['type']:
            return self.get_type_string_for_type(self.value['type']['Map']['key'])

    def get_params_type_string(self):
        if 'Plain' in self.value['type']:
            return []
        elif 'Map' in self.value['type']:
            key_type_string = self.get_type_string_for_type(self.value['type']['Map']['key'])
            nmap_key_scale_type = self.runtime_config.get_decoder_class(key_type_string)

            if nmap_key_scale_type.type_mapping and nmap_key_scale_type.scale_info_type['def'][0] == 'tuple' and \
                    len(self.get_param_hashers()) > 1:
                # In case of tuple and multiple param hashers extract type_mapping as separate parameters
                return nmap_key_scale_type.type_mapping
            else:
                return [key_type_string]
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


class GenericEventMetadata(Struct):

    @property
    def name(self):
        return self.value['name']

    @property
    def args(self):
        return self.value_object['args']

    @property
    def docs(self):
        return self.value['documentation']


class GenericErrorMetadata(Struct):

    @property
    def name(self):
        return self.value['name']

    @property
    def docs(self):
        return self.value['documentation']


class GenericModuleConstantMetadata(Struct):

    @property
    def name(self):
        return self.value['name']

    @property
    def type(self):
        return self.convert_type(self.value['type'])

    @property
    def docs(self):
        return self.value['documentation']

    @property
    def constant_value(self):
        if self.value_object.get('value'):
            return self.value_object['value'].value_object


class ScaleInfoModuleConstantMetadata(GenericModuleConstantMetadata):

    @property
    def type(self):
        return f"scale_info::{self.value['type']}"


class ScaleInfoFunctionArgumentMetadata(GenericFunctionArgumentMetadata):

    @property
    def type(self):
        if self.value.get('typeName'):
            return self.value.get('typeName')
        else:
            return f"scale_info::{self.value['type']}"


class TypeNotSupported(ScaleType):

    def process(self):
        raise ValueError(f"Scale type '{self.sub_type}' not support")

    def process_encode(self, value):
        raise ValueError(f"Scale type '{self.sub_type}' not support")


class GenericExtrinsic(ScaleType):

    def __init__(self, *arg, **kwargs):
        self.signed = None
        super().__init__(*arg, **kwargs)

    @property
    def extrinsic_hash(self):
        return blake2b(self.data.data, digest_size=32).digest()

    def process(self):
        self.value_object = {
            'extrinsic_length': self.process_type('Compact<u32>'),
        }

        value = {}

        version = self.process_type('u8').value

        self.signed = (version & 128) == 128

        if self.signed:
            extrinsic_versions = (
                'TypeNotSupported<ExtrinsicV0>',
                'TypeNotSupported<ExtrinsicV1>',
                'TypeNotSupported<ExtrinsicV2>',
                'TypeNotSupported<ExtrinsicV3>',
                'ExtrinsicV4'
            )
            extrinsic_version_idx = version & 127
            if extrinsic_version_idx >= len(extrinsic_versions):
                raise ValueError(f"Unsupported Extrinsic version '{extrinsic_version_idx}'")

            extrinsic_version = extrinsic_versions[extrinsic_version_idx]

            self.value_object.update(self.process_type(extrinsic_version, metadata=self.metadata).value_object)
            value['extrinsic_hash'] = f'0x{self.extrinsic_hash.hex()}'
        else:
            self.value_object.update(self.process_type('Inherent', metadata=self.metadata).value_object)
            value['extrinsic_hash'] = None

        value.update({key: value.serialize() for (key, value) in self.value_object.items()})

        return value

    def process_encode(self, value):

        # Backwards compatibility cases
        if 'address' not in value and 'account_id' in value:
            value['address'] = value['account_id']

        if 'signature_version' in value:
            multisig_cls = self.runtime_config.get_decoder_class('MultiSignature')
            value['signature'] = {
                multisig_cls.type_mapping[value['signature_version']][0]: value['signature']
            }

        if 'call' not in value:
            value['call'] = {
                'call_function': value.get('call_function'),
                'call_module': value.get('call_module'),
                'call_args': value.get('call_args'),
            }

        # Determine version (Fixed to V4 for now)
        if 'address' in value:
            data = ScaleBytes('0x84')
            self.signed = True
        else:
            data = ScaleBytes('0x04')
            self.signed = False

        self.value_object = {}

        if self.signed:
            extrinsic = self.runtime_config.create_scale_object('ExtrinsicV4', metadata=self.metadata)
        else:
            extrinsic = self.runtime_config.create_scale_object('Inherent', metadata=self.metadata)

        data += extrinsic.encode(value)
        self.value_object.update(extrinsic.value_object)

        # Wrap payload with a length Compact<u32>
        length_obj = self.runtime_config.create_scale_object('Compact<u32>')
        data = length_obj.encode(data.length) + data

        self.value_object['extrinsic_length'] = length_obj

        return data


class Extrinsic(GenericExtrinsic):
    pass


class GenericExtrinsicV4(Struct):

    def __init__(self, *args, **kwargs):

        if 'metadata' in kwargs and 'extrinsic' in kwargs['metadata'][1][1]:

            # Process signed extensions in metadata
            signed_extensions = kwargs['metadata'].get_signed_extensions()

            if len(signed_extensions) > 0:
                # Build type mapping according to signed extensions in metadata
                self.type_mapping = [['address', 'Address'], ['signature', 'ExtrinsicSignature']]

                if 'CheckMortality' in signed_extensions:
                    self.type_mapping.append(['era', signed_extensions['CheckMortality']['extrinsic']])

                if 'CheckEra' in signed_extensions:
                    self.type_mapping.append(['era', signed_extensions['CheckEra']['extrinsic']])

                if 'CheckNonce' in signed_extensions:
                    self.type_mapping.append(['nonce', signed_extensions['CheckNonce']['extrinsic']])

                if 'ChargeTransactionPayment' in signed_extensions:
                    self.type_mapping.append(['tip', signed_extensions['ChargeTransactionPayment']['extrinsic']])

                if 'ChargeAssetTxPayment' in signed_extensions:
                    self.type_mapping.append(['asset_id', signed_extensions['ChargeAssetTxPayment']['extrinsic']])

                self.type_mapping.append(['call', 'Call'])

        super().__init__(*args, **kwargs)


class GenericEvent(Enum):

    def __init__(self, *args, **kwargs):

        self.event_idx = None
        self.event_index = None
        self.attributes = []
        self.event = None
        self.event_module = None

        super().__init__(*args, **kwargs)

    def process(self):

        self.event_index = self.get_next_bytes(2).hex()

        # Decode attributes
        self.event_module = self.metadata.event_index[self.event_index][0]
        self.event = self.metadata.event_index[self.event_index][1]

        attributes_value = []

        for arg_type in self.event.value['args']:
            arg_type_obj = self.process_type(arg_type)

            self.attributes.append(arg_type_obj)

            attributes_value.append({
                'type': arg_type,
                'value': arg_type_obj.serialize()
            })

        self.value_object = {
            'metadata_pallet': self.event_module,
            'metadata_event': self.event,
            'attributes': self.attributes
        }

        return {
            'event_index': self.event_index,
            'module_id': self.event_module.value['name'],
            'event_id': self.event.value['name'],
            'attributes': attributes_value,
        }


class GenericScaleInfoEvent(Enum):

    def __init__(self, *args, **kwargs):

        self.event_index = None
        self.event = None
        self.event_module = None

        super().__init__(*args, **kwargs)

    def process(self):

        super().process()

        self.event_index = bytes([self.index, self.value_object[1].index]).hex()

        return {
            'event_index': self.event_index,
            'module_id': self.value_object[0],
            'event_id': self.value_object[1][0],
            'attributes': self.value_object[1][1].value if self.value_object[1][1] else None,
        }


class GenericEventRecord(Struct):

    @property
    def extrinsic_idx(self):
        return self.value['extrinsic_idx']

    @property
    def event_module(self):
        return self.value_object['event'].event_module

    @property
    def event(self):
        return self.value_object['event'].event

    @property
    def params(self):
        return self.value['attributes']

    def process(self):
        value = super().process()

        if self.value_object['phase'][0] == 'ApplyExtrinsic':
            extrinsic_idx = self.value_object['phase'][1].value
        else:
            extrinsic_idx = None

        return {
            'phase': self.value_object['phase'][0],
            'extrinsic_idx': extrinsic_idx,
            'event': value['event'],
            'event_index': self.value_object['event'].index,
            'module_id': value['event']['module_id'],
            'event_id': value['event']['event_id'],
            'attributes': value['event']['attributes'],
            'topics': value['topics']
        }


class EventRecord(Struct):

    def __init__(self, *arg, **kwargs):

        self.phase = None
        self.extrinsic_idx = None
        self.event_index = None
        self.params = []
        self.event = None
        self.event_module = None
        self.topics = []
        self.arguments = []

        super().__init__(*arg, **kwargs)

    def process(self):

        self.phase = self.process_type('Phase')

        if self.phase.index == 0:
            self.extrinsic_idx = self.phase.value_object[1].value

        self.event_index = self.get_next_bytes(2).hex()

        # Decode params
        self.event_module = self.metadata.event_index[self.event_index][0]
        self.event = self.metadata.event_index[self.event_index][1]

        for arg_type in self.event.value['args']:
            arg_type_obj = self.process_type(arg_type)

            self.params.append({
                'type': arg_type,
                'value': arg_type_obj.serialize()
            })

        # Topics introduced since MetadataV5
        if self.metadata and self.metadata.value_object[1].index >= 5:
            self.topics = self.process_type('Vec<Hash>').value

        return {
            'phase': self.phase.index,
            'extrinsic_idx': self.extrinsic_idx,
            'event_index': self.event_index,
            'module_id': self.event_module.value['name'],
            'event_id': self.event.value['name'],
            'params': self.params,
            'topics': self.topics
        }


class GenericConsensusEngineId(FixedLengthArray):
    sub_type = 'u8'
    element_count = 4

    def process(self):
        return self.get_next_bytes(self.element_count).decode()


class GenericSealV0(Struct):
    type_string = '(u64, Signature)'

    type_mapping = (('slot', 'u64'), ('signature', 'Signature'))


class GenericConsensus(Struct):
    type_string = '(ConsensusEngineId, Vec<u8>)'

    type_mapping = (('engine', 'ConsensusEngineId'), ('data', 'HexBytes'))


class GenericSeal(Struct):
    type_string = '(ConsensusEngineId, Bytes)'

    type_mapping = (('engine', 'ConsensusEngineId'), ('data', 'HexBytes'))


class GenericPreRuntime(Struct):

    type_mapping = (('engine', 'ConsensusEngineId'), ('data', 'HexBytes'))

    def __init__(self, data, **kwargs):
        self.authority_index = None
        self.slot_number = None
        super().__init__(data, **kwargs)

    def process(self):

        value = super().process()

        if value['engine'] == 'BABE':
            # Determine block producer
            babe_predigest = self.runtime_config.create_scale_object(
                type_string='RawBabePreDigest',
                data=ScaleBytes(bytearray.fromhex(value['data'].replace('0x', '')))
            )

            babe_predigest.decode()

            if len(list(babe_predigest.value.values())) > 0:
                babe_predigest_value = list(babe_predigest.value.values())[0]

                value['data'] = babe_predigest_value
                self.authority_index = babe_predigest_value['authority_index']
                self.slot_number = babe_predigest_value['slot_number']

        if value['engine'] == 'aura':

            aura_predigest = self.runtime_config.create_scale_object(
                type_string='RawAuraPreDigest',
                data=ScaleBytes(bytearray.fromhex(value['data'].replace('0x', '')))
            )
            aura_predigest.decode()

            value['data'] = aura_predigest.value
            self.slot_number = aura_predigest.value['slot_number']

        return value


class LogDigest(Enum):

    value_list = ['Other', 'AuthoritiesChange', 'ChangesTrieRoot', 'SealV0', 'Consensus', 'Seal', 'PreRuntime']

    def __init__(self, data, **kwargs):
        warnings.warn("LogDigest will be removed in future releases", DeprecationWarning)
        self.log_type = None
        self.index_value = None
        super().__init__(data, **kwargs)

    def process(self):
        self.index = int(self.get_next_bytes(1).hex())
        self.index_value = self.value_list[self.index]
        self.log_type = self.process_type(self.value_list[self.index])

        return {'type': self.value_list[self.index], 'value': self.log_type.value}
