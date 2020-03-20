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

import re
from abc import ABC, abstractmethod

from scalecodec.exceptions import RemainingScaleBytesNotEmptyException, InvalidScaleTypeValueException


class Singleton(type):
    _instances = {}

    def __call__(cls, *args, **kwargs):
        if cls not in cls._instances:
            cls._instances[cls] = super(Singleton, cls).__call__(*args, **kwargs)
        return cls._instances[cls]


class RuntimeConfiguration(metaclass=Singleton):

    @classmethod
    def all_subclasses(cls, class_):
        return set(class_.__subclasses__()).union(
            [s for c in class_.__subclasses__() for s in cls.all_subclasses(c)])

    def __init__(self):
        self.type_registry = {}
        self.clear_type_registry()
        self.active_spec_version_id = None

    def get_decoder_class(self, type_string, spec_version_id='default'):
        # TODO move ScaleDecoder.get_decoder_class logic to here
        return self.type_registry.get('types', {}).get(type_string.lower(), None)

    def clear_type_registry(self):
        self.type_registry = {'types': {cls.type_string.lower(): cls for cls in self.all_subclasses(ScaleDecoder) if
                                        cls.type_string}}
        self.type_registry['types'].update({cls.__name__.lower(): cls for cls in self.all_subclasses(ScaleDecoder)})

    def update_type_registry_types(self, types_dict):
        from scalecodec.types import Enum, Struct, Set

        for type_string, decoder_class_data in types_dict.items():

            if type(decoder_class_data) == dict:

                # Create dynamic decoder class
                if decoder_class_data['type'] == 'struct':

                    decoder_class = type(type_string, (Struct,), {'type_mapping': decoder_class_data['type_mapping']})

                elif decoder_class_data['type'] == 'enum':

                    decoder_class = type(type_string, (Enum,), {
                        'value_list': decoder_class_data.get('value_list'),
                        'type_mapping': decoder_class_data.get('type_mapping')
                    })

                elif decoder_class_data['type'] == 'set':

                    decoder_class = type(type_string, (Set,), {
                        'value_list': decoder_class_data.get('value_list'),
                        'value_type': decoder_class_data.get('value_type', 'u64')
                    })

                else:
                    raise NotImplementedError("Dynamic decoding type '{}' not supported".format(
                        decoder_class_data['type'])
                    )
            else:
                decoder_class = self.get_decoder_class(decoder_class_data)

            self.type_registry['types'][type_string.lower()] = decoder_class

    def update_type_registry(self, type_registry):

        # Set runtime ID if set
        self.active_spec_version_id = type_registry.get('runtime_id')

        # Set versioning
        if 'versioning' in type_registry:
            self.type_registry['versioning'] = type_registry.get('versioning')

        # Update types
        if 'types' in type_registry:
            self.update_type_registry_types(type_registry.get('types'))

    def set_active_spec_version_id(self, spec_version_id):

        if spec_version_id != self.active_spec_version_id:

            self.active_spec_version_id = spec_version_id

            # Updated type registry with versioned types
            for versioning_item in self.type_registry.get('versioning', []):
                # Check if versioning item is in current version range
                if versioning_item['runtime_range'][0] <= spec_version_id and \
                        (not versioning_item['runtime_range'][1] or versioning_item['runtime_range'][1] >= spec_version_id):
                    # Update types in type registry
                    self.update_type_registry_types(versioning_item['types'])


class ScaleBytes:

    def __init__(self, data):
        self.offset = 0

        if type(data) is bytearray:
            self.data = data
        elif data[0:2] == '0x':
            self.data = bytearray.fromhex(data[2:])
        else:
            raise ValueError("Provided data is not in supported format: provided '{}'".format(type(data)))

        self.length = len(self.data)

    def get_next_bytes(self, length):
        data = self.data[self.offset:self.offset + length]
        self.offset += length
        return data

    def get_remaining_bytes(self):
        data = self.data[self.offset:]
        self.offset = self.length
        return data

    def get_remaining_length(self):
        return self.length - self.offset

    def reset(self):
        self.offset = 0

    def __str__(self):
        return "0x{}".format(self.data.hex())

    def __add__(self, data):

        if type(data) == ScaleBytes:
            return ScaleBytes(self.data + data.data)

        if type(data) == bytes:
            data = bytearray(data)
        elif type(data) == str and data[0:2] == '0x':
            data = bytearray.fromhex(data[2:])

        if type(data) == bytearray:
            return ScaleBytes(self.data + data)


class ScaleDecoder(ABC):

    type_string = None

    type_mapping = None

    debug = False

    PRIMITIVES = ('bool', 'u8', 'u16', 'u32', 'u64', 'u128', 'u256', 'i8', 'i16', 'i32', 'i64', 'i128', 'i256', 'h160',
                  'h256', 'h512', '[u8; 4]', '[u8; 4]', '[u8; 8]', '[u8; 16]', '[u8; 32]', '&[u8]')

    def __init__(self, data, sub_type=None):

        self.sub_type = sub_type

        if self.type_mapping is None and self.type_string:
            self.build_type_mapping()

        if data:
            assert(type(data) == ScaleBytes)

        self.data = data
        self.raw_value = ''
        self.value = None

    @classmethod
    def build_type_mapping(cls):

        if cls.type_string and cls.type_string[0] == '(' and cls.type_string[-1] == ')':
            type_mapping = ()

            tuple_contents = cls.type_string[1:-1]

            # replace subtype types
            sub_types = re.search(r'([A-Za-z]+[<][^>]*[>])', tuple_contents)
            if sub_types:
                sub_types = sub_types.groups()
                for sub_type in sub_types:
                    tuple_contents = tuple_contents.replace(sub_type, sub_type.replace(',', ';'))

            n = 1
            for struct_element in tuple_contents.split(','):
                type_mapping += (('col{}'.format(n), struct_element.strip().replace(';', ',')),)
                n += 1

            cls.type_mapping = type_mapping

    def get_next_bytes(self, length):
        data = self.data.get_next_bytes(length)
        self.raw_value += data.hex()
        return data

    def get_next_u8(self):
        return int.from_bytes(self.get_next_bytes(1), byteorder='little')

    def get_next_bool(self):
        data = self.get_next_bytes(1)
        if data not in [b'\x00', b'\x01']:
            raise InvalidScaleTypeValueException('Invalid value for datatype "bool"')
        return data == b'\x01'

    def get_remaining_bytes(self):
        data = self.data.get_remaining_bytes()
        self.raw_value += data.hex()
        return data

    @abstractmethod
    def process(self):
        pass

    def decode(self, check_remaining=True):
        self.value = self.process()

        if check_remaining and self.data.offset != self.data.length:
            raise RemainingScaleBytesNotEmptyException('Current offset: {} / length: {}'.format(self.data.offset, self.data.length))

        if self.data.offset > self.data.length:
            raise RemainingScaleBytesNotEmptyException(
                'No more bytes available (offset: {} / length: {})'.format(self.data.offset, self.data.length))

        return self.value

    def __str__(self):
        return str(self.value) or ''

    def encode(self, value):
        self.data = self.process_encode(value)
        return self.data

    def process_encode(self, value):
        raise NotImplementedError("Encoding not implemented for this ScaleType")

    @classmethod
    def get_decoder_class(cls, type_string, data=None, **kwargs):

        type_parts = None

        type_string = cls.convert_type(type_string)

        if type_string[-1:] == '>':
            # Check for specific implementation for composite type
            decoder_class = RuntimeConfiguration().get_decoder_class(
                type_string.lower(),
                spec_version_id=kwargs.get('spec_version_id', 'default')
            )

            if decoder_class:
                return decoder_class(data, **kwargs)

            # Extract sub types
            type_parts = re.match(r'^([^<]*)<(.+)>$', type_string)

            if type_parts:
                type_parts = type_parts.groups()

        if type_parts:
            decoder_class = RuntimeConfiguration().get_decoder_class(
                type_parts[0].lower(),
                spec_version_id=kwargs.get('spec_version_id', 'default')
            )
            if decoder_class:
                return decoder_class(data, sub_type=type_parts[1], **kwargs)
        else:
            decoder_class = RuntimeConfiguration().get_decoder_class(
                type_string.lower(),
                spec_version_id=kwargs.get('spec_version_id', 'default')
            )
            if decoder_class:
                return decoder_class(data, **kwargs)

        # Custom tuple
        # TODO tuples should be converted to list not dict
        if type_string != '()' and type_string[0] == '(' and type_string[-1] == ')':
            decoder_class = RuntimeConfiguration().get_decoder_class('struct')
            decoder_class.type_string = type_string

            decoder_class.build_type_mapping()

            return decoder_class(data, **kwargs)

        raise NotImplementedError('Decoder class for "{}" not found'.format(type_string))

    # TODO rename to decode_type (confusing when encoding is introduced)
    def process_type(self, type_string, **kwargs):
        obj = self.get_decoder_class(type_string, self.data, **kwargs)
        obj.decode(check_remaining=False)
        if self.debug:
            print('=======================\nClass:\t{}\nType:\t{}\nValue:\t{}\nRaw:\t{}\n\nOffset:\t{} / {}\n'.format(
                self.__class__.__name__, type_string, obj.value, obj.raw_value, self.data.offset, self.data.length
            ))
        return obj

    def serialize(self):
        return self.value

    # TODO convert to TYPE_ALIAS per class Address: TYPE_ALIAS = ('<Lookup as StaticLookup>::Source',)
    @classmethod
    def convert_type(cls, name):

        name = re.sub(r'T::', "", name)
        name = re.sub(r'<T>', "", name)
        name = re.sub(r'<T as Trait>::', "", name)
        name = re.sub(r'\n', "", name)
        name = re.sub(r'(grandpa|session|slashing)::', "", name)

        if name == '()':
            return "Null"
        if name in ['Vec<u8>', '&[u8]']:
            return "Bytes"
        if name == '<Lookup as StaticLookup>::Source':
            return 'Address'
        if name == 'Vec<<Lookup as StaticLookup>::Source>':
            return 'Vec<Address>'
        if name == '<Balance as HasCompact>::Type':
            return 'Compact<Balance>'
        if name == '<BlockNumber as HasCompact>::Type':
            return 'Compact<BlockNumber>'
        if name == '<Balance as HasCompact>::Type':
            return 'Compact<Balance>'
        if name == '<Moment as HasCompact>::Type':
            return 'Compact<Moment>'
        if name == '<InherentOfflineReport as InherentOfflineReport>::Inherent':
            return 'InherentOfflineReport'
        if name == 'RawAddress':
            return 'Address'

        return name


# TODO move type_string and sub_type behaviour to this sub class
class ScaleType(ScaleDecoder, ABC):

    def __init__(self, data=None, sub_type=None, metadata=None):
        self.metadata = metadata
        if not data:
            data = ScaleBytes(bytearray())
        super().__init__(data, sub_type)
