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

from datetime import datetime
from hashlib import blake2b
from scalecodec.base import ScaleType, ScaleBytes
from scalecodec.exceptions import InvalidScaleTypeValueException
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

        if self.sub_type:

            byte_data = self.get_decoder_class(self.sub_type, ScaleBytes(self.compact_bytes)).process()

            if type(byte_data) is int and self.compact_length <= 4:
                return int(byte_data / 4)
            else:
                return byte_data
        else:
            return self.compact_bytes

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
            return self.process_type(self.sub_type).value

        return None

    def process_encode(self, value):

        if value is not None and self.sub_type:
            sub_type_obj = self.get_decoder_class(self.sub_type)
            return ScaleBytes('0x01') + sub_type_obj.encode(value)

        return ScaleBytes('0x00')


class Bytes(ScaleType):

    type_string = 'Vec<u8>'

    def process(self):

        length = self.process_type('Compact<u32>').value
        value = self.get_next_bytes(length)

        try:
            return value.decode()
        except UnicodeDecodeError:
            return '0x{}'.format(value.hex())

    def process_encode(self, value):
        string_length_compact = CompactU32()

        if value[0:2] == '0x':
            # TODO implicit HexBytes conversion can have unexpected result if string is actually starting with '0x'
            value = bytes.fromhex(value[2:])
            data = string_length_compact.encode(len(value))
            data += value
        else:
            data = string_length_compact.encode(len(value))
            data += value.encode()

        return data


class OptionBytes(ScaleType):

    type_string = 'Option<Vec<u8>>'

    def process(self):

        option_byte = self.get_next_bytes(1)

        if option_byte != b'\x00':
            return self.process_type('Bytes').value

        return None


# TODO replace in metadata
class String(ScaleType):

    def process(self):

        length = self.process_type('Compact<u32>').value
        value = self.get_next_bytes(length)

        return value.decode()

    def process_encode(self, value):
        string_length_compact = CompactU32()
        data = string_length_compact.encode(len(value))
        data += value.encode()
        return data


class HexBytes(ScaleType):

    def process(self):

        length = self.process_type('Compact<u32>').value

        return '0x{}'.format(self.get_next_bytes(length).hex())

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

    def process_encode(self, value):
        if value[0:2] != '0x' or len(value) != 130:
            raise ValueError('Value should start with "0x" and should be 64 bytes long')
        return ScaleBytes(value)


class Struct(ScaleType):

    def __init__(self, data, type_mapping=None, **kwargs):

        if type_mapping:
            self.type_mapping = type_mapping

        super().__init__(data, **kwargs)

    def process(self):

        result = {}

        for key, data_type in self.type_mapping:
            if data_type is None:
                data_type = 'Null'
            result[key] = self.process_type(data_type, metadata=self.metadata).value

        return result

    def process_encode(self, value):
        data = ScaleBytes(bytearray())

        if type(value) is list:
            if len(value) != len(self.type_mapping):
                raise ValueError('Element count of value ({}) doesn\'t match type_mapping ({})'.format(len(value), len(self.type_mapping)))

            for idx, (key, data_type) in enumerate(self.type_mapping):

                element_obj = self.get_decoder_class(data_type, metadata=self.metadata)
                data += element_obj.encode(value[idx])

        else:
            for key, data_type in self.type_mapping:
                if key not in value:
                    raise ValueError('Element "{}" of struct is missing in given value'.format(key))

                element_obj = self.get_decoder_class(data_type, metadata=self.metadata)
                data += element_obj.encode(value[key])

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

        u64_obj = self.get_decoder_class(self.value_type)

        return u64_obj.encode(result)


class Era(ScaleType):
    """
    An Era represents a range of blocks in which a transaction is allowed to be
    executed.

    An Era may either be "immortal", in which case the transaction is always valid,
    or "mortal", in which case the transaction has a defined start block and period
    in which it is valid.
    """

    def __init__(self, data=None, sub_type=None, metadata=None):
        self.period = None
        self.phase = None
        super().__init__(data, sub_type, metadata)

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

    def process(self):
        int_value = super().process()

        if int_value > 10000000000:
            int_value = int_value / 1000

        return datetime.utcfromtimestamp(int_value)

    def serialize(self):
        return self.value.isoformat()


class BoxProposal(ScaleType):
    type_string = 'Box<Proposal>'

    def __init__(self, data, **kwargs):
        self.call_index = None
        self.call_function = None
        self.call_module = None
        self.call_args = []
        super().__init__(data, **kwargs)

    def process(self):

        self.call_index = self.get_next_bytes(2).hex()

        self.call_module, self.call_function = self.metadata.call_index[self.call_index]

        for arg in self.call_function.args:
            arg_type_obj = self.process_type(arg.type, metadata=self.metadata)

            self.call_args.append({
                'name': arg.name,
                'type': arg.type,
                'value': arg_type_obj.serialize(),
                'valueRaw': arg_type_obj.raw_value
            })

        return {
            'call_index': self.call_index,
            'call_function': self.call_function.name,
            'call_module': self.call_module.name,
            'call_args': self.call_args
        }

    def process_encode(self, value):
        # Check requirements
        if 'call_index' in value:
            self.call_index = value['call_index']

        elif 'call_module' in value and 'call_function' in value:
            # Look up call module from metadata
            for call_index, (call_module, call_function) in self.metadata.call_index.items():

                if call_module.name == value['call_module'] and call_function.name == value['call_function']:
                    self.call_index = call_index
                    self.call_module = call_module
                    self.call_function = call_function
                    break

            if not self.call_index:
                raise ValueError('Specified call module and function not found in metadata')

        elif not self.call_module or not self.call_function:
            raise ValueError('No call module and function specified')

        data = ScaleBytes(bytearray.fromhex(self.call_index))

        # Encode call params
        if len(self.call_function.args) > 0:
            for arg in self.call_function.args:
                if arg.name not in value['call_args']:
                    raise ValueError('Parameter \'{}\' not specified'.format(arg.name))
                else:
                    param_value = value['call_args'][arg.name]

                    arg_obj = self.get_decoder_class(arg.type, metadata=self.metadata)
                    data += arg_obj.encode(param_value)

        return data


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
        result['proposal'] = Proposal(ScaleBytes(result['proposal']), metadata=self.metadata).decode()

        return result


class Proposal(BoxProposal):
    type_string = '<T as Trait<I>>::Proposal'


class ValidatorPrefs(Struct):
    type_string = '(Compact<Balance>)'

    type_mapping = (('commission', 'Compact<Balance>'),)


class ValidatorPrefsLegacy(Struct):
    type_string = '(Compact<u32>,Compact<Balance>)'

    type_mapping = (('unstakeThreshold', 'Compact<u32>'), ('validatorPayment', 'Compact<Balance>'))


class Linkage(Struct):
    type_string = 'Linkage<AccountId>'

    type_mapping = (
        ('previous', 'Option<AccountId>'),
        ('next', 'Option<AccountId>')
    )


class GenericAccountId(H256):

    def __init__(self, data=None, sub_type=None, metadata=None):
        self.ss58_address = None
        super().__init__(data, sub_type, metadata)

    def process_encode(self, value):
        if value[0:2] != '0x' and len(value) == 47:
            from scalecodec.utils.ss58 import ss58_decode
            self.ss58_address = value
            value = '0x{}'.format(ss58_decode(value))
        return super().process_encode(value)


class GenericAccountIndex(U32):
    pass


class KeyValue(Struct):
    type_string = '(Vec<u8>, Vec<u8>)'
    type_mapping = (('key', 'Vec<u8>'), ('value', 'Vec<u8>'))


class NewAccountOutcome(CompactU32):
    type_string = 'NewAccountOutcome'


class Vec(ScaleType):

    def __init__(self, data=None, **kwargs):
        self.elements = []
        super().__init__(data, **kwargs)

    def process(self):
        element_count = self.process_type('Compact<u32>').value

        result = []
        for _ in range(0, element_count):
            element = self.process_type(self.sub_type, metadata=self.metadata)
            self.elements.append(element)
            result.append(element.value)

        return result

    def process_encode(self, value):

        if type(value) is not list:
            raise ValueError("Provided value is not a list")

        # encode element count to Compact<u32>
        element_count_compact = CompactU32()

        element_count_compact.encode(len(value))

        data = element_count_compact.data

        for element in value:

            element_obj = self.get_decoder_class(self.sub_type, metadata=self.metadata)
            data += element_obj.encode(element)

        return data


class BitVec(Vec):
    # TODO: A BitVec that represents an array of bits. The bits are however stored encoded. The difference between this
    #  * and a normal Bytes would be that the length prefix indicates the number of bits encoded, not the bytes
    pass


class GenericAddress(ScaleType):

    def __init__(self, data, **kwargs):
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

    def __init__(self, data, value_list=None, type_mapping=None, **kwargs):

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
                return self.process_type('Struct', type_mapping=[enum_type_mapping]).value

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
                raise ValueError("Value must be a dict when type_mapping is set, not '{}'".format(value))

            if len(value) != 1:
                raise ValueError("Value for enum with type_mapping can only have one value")

            for enum_key, enum_value in value.items():
                for idx, (item_key, item_value) in enumerate(self.type_mapping):
                    if item_key == enum_key:
                        self.index = idx
                        struct_obj = self.get_decoder_class('Struct', type_mapping=[self.type_mapping[self.index]])
                        return ScaleBytes(bytearray([self.index])) + struct_obj.encode(value)

                raise ValueError("Value '{}' not present in type_mapping of this enum".format(enum_key))

        else:
            for idx, item in enumerate(self.value_list):
                if item == value:
                    self.index = idx
                    return ScaleBytes(bytearray([self.index]))

            raise ValueError("Value '{}' not present in value list of this enum".format(value))

    def get_enum_value(self):
        if self.value:

            if self.type_mapping:
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

        elif self.index >= 1 and self.index <= 33:
            # Determine value of Raw type (length is processed in index byte)
            data = self.get_next_bytes(self.index - 1)

            try:
                value = data.decode()
            except UnicodeDecodeError:
                value = '0x{}'.format(data.hex())
            return {"Raw": value}

        elif self.index >= 34 and self.index <= 37:

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

                        struct_obj = self.get_decoder_class('Struct', type_mapping=[self.type_mapping[self.index]])
                        return ScaleBytes(bytearray([self.index])) + struct_obj.encode(value)

            raise ValueError("Value '{}' not present in type_mapping of this enum".format(enum_key))


class Null(ScaleType):

    def process(self):
        return None

    def process_encode(self, value):
        return ScaleBytes(bytearray())


class InherentOfflineReport(Null):
    pass


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


class LockPeriods(U8):
    pass


class SessionKey(H256):
    pass


class PrefabWasmModule(Struct):
    type_string = 'wasm::PrefabWasmModule'

    type_mapping = (
        ('scheduleVersion', 'Compact<u32>'),
        ('initial', 'Compact<u32>'),
        ('maximum', 'Compact<u32>'),
        ('_reserved', 'Option<Null>'),
        ('code', 'Bytes'),
    )


class SessionKeysSubstrate(Struct):

    type_mapping = (
        ('grandpa', 'AccountId'),
        ('babe', 'AccountId'),
        ('im_online', 'AccountId'),
    )


class LegacyKeys(Struct):

    type_mapping = (
        ('grandpa', 'AccountId'),
        ('babe', 'AccountId'),
    )


class EdgewareKeys(Struct):
    type_mapping = (
        ('grandpa', 'AccountId'),
    )


class QueuedKeys(Struct):

    type_string = '(ValidatorId, Keys)'

    type_mapping = (
        ('validator', 'ValidatorId'),
        ('keys', 'Keys'),
    )


class LegacyQueuedKeys(Struct):

    type_string = '(ValidatorId, LegacyKeys)'

    type_mapping = (
        ('validator', 'ValidatorId'),
        ('keys', 'LegacyKeys'),
    )


class EdgewareQueuedKeys(Struct):

    type_string = '(ValidatorId, EdgewareKeys)'

    type_mapping = (
        ('validator', 'ValidatorId'),
        ('keys', 'EdgewareKeys'),
    )


class VecQueuedKeys(Vec):
    type_string = 'Vec<(ValidatorId, Keys)>'

    def process(self):
        element_count = self.process_type('Compact<u32>').value
        result = []
        for _ in range(0, element_count):
            element = self.process_type('QueuedKeys')
            self.elements.append(element)
            result.append(element.value)

        return result


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
    pass


class GenericCall(ScaleType):

    type_string = "Box<Call>"

    def __init__(self, data, **kwargs):
        self.call_index = None
        self.call_function = None
        self.call_args = []
        self.call_module = None

        super().__init__(data, **kwargs)

    def process(self):

        self.call_index = self.get_next_bytes(2).hex()

        self.call_module, self.call_function = self.metadata.call_index[self.call_index]

        for arg in self.call_function.args:
            arg_type_obj = self.process_type(arg.type, metadata=self.metadata)

            self.call_args.append({
                'name': arg.name,
                'type': arg.type,
                'value': arg_type_obj.serialize(),
                'valueRaw': arg_type_obj.raw_value
            })

        return {
            'call_index': self.call_index,
            'call_function': self.call_function.name,
            'call_module': self.call_module.name,
            'call_args': self.call_args
        }

    def process_encode(self, value):

        if type(value) is not dict:
            raise TypeError("value must be of type dict to encode a GenericCall")

        # Check requirements
        if 'call_index' in value:
            self.call_index = value['call_index']

        elif 'call_module' in value and 'call_function' in value:
            # Look up call module from metadata
            for call_index, (call_module, call_function) in self.metadata.call_index.items():

                if call_module.name == value['call_module'] and call_function.name == value['call_function']:
                    self.call_index = call_index
                    self.call_module = call_module
                    self.call_function = call_function
                    break

            if not self.call_index:
                raise ValueError('Specified call module and function not found in metadata')

        elif not self.call_module or not self.call_function:
            raise ValueError('No call module and function specified')

        data = ScaleBytes(bytearray.fromhex(self.call_index))

        # Encode call params
        if len(self.call_function.args) > 0:
            for arg in self.call_function.args:
                if arg.name not in value['call_args']:
                    raise ValueError('Parameter \'{}\' not specified'.format(arg.name))
                else:
                    param_value = value['call_args'][arg.name]

                    arg_obj = self.get_decoder_class(arg.type, metadata=self.metadata)
                    data += arg_obj.encode(param_value)
        return data


class OpaqueCall(Bytes):

    def process_encode(self, value):
        call_obj = self.get_decoder_class('Call', metadata=self.metadata)
        return super().process_encode(str(call_obj.encode(value)))

    def process(self):
        value = super().process()
        try:
            call_obj = self.get_decoder_class(
                type_string='Call',
                data=ScaleBytes('0x{}'.format(self.raw_value)),
                metadata=self.metadata
            )

            return call_obj.process()
        except:
            return value


class MultiAccountId(GenericAccountId):

    @classmethod
    def create_from_account_list(cls, accounts, threshold):
        from scalecodec.utils.ss58 import ss58_decode

        account_ids = []
        for account in accounts:
            if account[0:2] != '0x':
                account = '0x{}'.format(ss58_decode(account))
            account_ids.append(account)

        account_list_cls = cls.get_decoder_class('Vec<AccountId>')
        account_list_data = account_list_cls.encode(sorted(account_ids))
        threshold_data = cls.get_decoder_class("u16").encode(threshold)

        multi_account_id = "0x{}".format(blake2b(
            b"modlpy/utilisuba" + bytes(account_list_data.data) + bytes(threshold_data.data), digest_size=32
        ).digest().hex())

        multi_account_obj = cls()
        multi_account_obj.encode(multi_account_id)

        return multi_account_obj


class FixedLengthArray(ScaleType):

    element_count = 0

    def process(self):

        if self.element_count:
            if self.sub_type == 'u8':
                return '0x{}'.format(self.get_next_bytes(self.element_count).hex())
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

        if self.sub_type == 'u8':
            # u8 arrays are represented as hex-bytes (e.g. [u8; 3] as 0x123456)
            if value[0:2] != '0x' or len(value[2:]) != self.element_count * 2:
                raise ValueError('Value should start with "0x" and should be {} bytes long'.format(self.element_count))

            return ScaleBytes(value)

        else:

            if not type(value) is list:
                raise ValueError('Given value is not a list')

            for element_value in value:
                element_obj = self.get_decoder_class(self.sub_type, metadata=self.metadata)
                data += element_obj.encode(element_value)

            return data
