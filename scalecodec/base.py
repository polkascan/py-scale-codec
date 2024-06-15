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
import copy
import re
import warnings
from abc import ABC, abstractmethod
from typing import Optional, TYPE_CHECKING, Union

from scalecodec.constants import TYPE_DECOMP_MAX_RECURSIVE
from scalecodec.exceptions import RemainingScaleBytesNotEmptyException, InvalidScaleTypeValueException

if TYPE_CHECKING:
    from scalecodec.types import GenericMetadataVersioned, GenericRegistryType


class ScaleBytes:
    """
    Representation of SCALE encoded Bytes.
    """

    def __init__(self, data: Union[str, bytes, bytearray]):
        """
        Constructs a SCALE bytes-stream with provided `data`

        Parameters
        ----------
        data
        """
        self.offset = 0

        if type(data) is bytearray:
            self.data = data
        elif type(data) is bytes:
            self.data = bytearray(data)
        elif type(data) is str and data[0:2] == '0x':
            self.data = bytearray.fromhex(data[2:])
        else:
            raise ValueError("Provided data is not in supported format: provided '{}'".format(type(data)))

        self.length = len(self.data)

    def get_next_bytes(self, length: int) -> bytearray:
        """
        Retrieve `length` amount of bytes of the stream

        Parameters
        ----------
        length: amount of requested bytes

        Returns
        -------
        bytearray
        """
        if self.offset + length > self.length:
            raise RemainingScaleBytesNotEmptyException(
                f'No more bytes available (needed: {self.offset + length} / total: {self.length})'
            )

        data = self.data[self.offset:self.offset + length]
        self.offset += length
        return data

    def get_remaining_bytes(self) -> bytearray:
        """
        Retrieves all remaining bytes from the stream

        Returns
        -------
        bytearray
        """

        data = self.data[self.offset:]
        self.offset = self.length
        return data

    def get_remaining_length(self) -> int:
        """
        Returns how many bytes are left in the stream

        Returns
        -------
        int
        """
        return self.length - self.offset

    def reset(self):
        """
        Resets the pointer of the stream to the beginning

        Returns
        -------

        """
        self.offset = 0


    def copy(self):
        return ScaleBytes(self.data)

    def __str__(self):
        return "0x{}".format(self.data.hex())

    def __eq__(self, other):
        if not hasattr(other, 'data'):
            return False
        return self.data == other.data

    def __len__(self):
        return len(self.data)

    def __repr__(self):
        return "<{}(data=0x{})>".format(self.__class__.__name__, self.data.hex())

    def __add__(self, data):

        if type(data) == ScaleBytes:
            return ScaleBytes(self.data + data.data)

        if type(data) == bytes:
            data = bytearray(data)
        elif type(data) == str and data[0:2] == '0x':
            data = bytearray.fromhex(data[2:])

        if type(data) == bytearray:
            return ScaleBytes(self.data + data)

    def to_hex(self) -> str:
        """
        Return a hex-string (e.g. "0x00") representation of the byte-stream

        Returns
        -------
        str
        """
        return f'0x{self.data.hex()}'


class ScaleTypeDef:

    scale_type_cls = None

    def __init__(self, name: str = None, metadata=None):
        if self.scale_type_cls is None:
            self.scale_type_cls = ScaleType
        self.name = name
        self.runtime_config = None
        self.metadata = metadata

    def new(self, **kwargs) -> 'ScaleType':
        # return self.scale_type_cls(type_def=self, metadata=self.metadata)
        return self.scale_type_cls(type_def=self, **kwargs)

    def impl(self, scale_type_cls: type = None, runtime_config=None) -> 'ScaleTypeDef':
        """

        Returns:
            object:
        """
        if scale_type_cls:
            self.scale_type_cls = scale_type_cls
        if runtime_config:
            self.runtime_config = runtime_config

        return self

    # def create_from_registry_type(self, registry_type):

    @abstractmethod
    def process_encode(self, value: any) -> ScaleBytes:
        pass

    def encode(self, value: any, external_call=True) -> ScaleBytes:

        if external_call:
            raise ValueError("encode of definition cannot be called directly")
        #
        # if issubclass(value.__class__, ScaleType):
        #     if value.type_def.__class__ is self.__class__:
        #         return value.data
        #     else:
        #         raise ValueError(f"Cannot encode '{value.type_def.__class__}' to a '{self.__class__}'")
        # else:
        return self.process_encode(value)

    @abstractmethod
    def decode(self, data: ScaleBytes) -> any:
        pass

    @abstractmethod
    def serialize(self, value: any) -> any:
        raise NotImplementedError()

    @abstractmethod
    def deserialize(self, value: any) -> any:
        raise NotImplementedError()

    # TODO implement

    @abstractmethod
    def example_value(self, _recursion_level: int = 0, max_recursion: int = TYPE_DECOMP_MAX_RECURSIVE):

        if _recursion_level > max_recursion:
            return self.__class__.__name__
        return self.__class__.__name__


class ScaleType:

    def __init__(self, type_def: ScaleTypeDef, metadata: 'GenericMetadataVersioned' = None):

        self.meta_info = None
        self.type_def: ScaleTypeDef = type_def
        self.value_serialized = None
        self.value_object = None
        self.metadata = metadata
        # self.runtime_config = runtime_config

        self._data = None
        self._data_start_offset = 0
        self._data_end_offset = 0

        super().__init__()

    # def __call__(self, *args, **kwargs):
    #     return self

    def encode(self, value: Optional[any] = None) -> ScaleBytes:
        if value is not None and issubclass(self.__class__, value.__class__):
            # Accept instance of current class directly
            self._data = value.data
            self.value_object = value.value_object
            self.value_serialized = value.value_serialized
            return value.data

        if value is None:
            value = self.value_serialized

        self._data = self.type_def.encode(value, False)
        self._data_start_offset = self._data.offset
        self._data_end_offset = self._data.length

        self.value_serialized = value
        self.value_object = self.deserialize(value)

        return self._data

    def decode(self, data: ScaleBytes, check_remaining=False) -> any:
        self._data = data
        self._data_start_offset = data.offset
        # Decode type
        self.value_object = self.type_def.decode(data)

        self._data_end_offset = data.offset

        self.value_serialized = self.serialize()
        return self.value_serialized

    def serialize(self) -> Union[int, str, dict, tuple, bool]:
        self.value_serialized = self.type_def.serialize(self.value_object)
        return self.value_serialized

    def deserialize(self, value_serialized: any):
        if value_serialized and issubclass(self.__class__, self.value_serialized.__class__):
            # Accept instance of current class directly
            self.value_object = self.value_serialized.value_object
            self.value_serialized = self.value_serialized.value_serialized
            return self.value_object

        self.value_object = self.type_def.deserialize(value_serialized)
        self.value_serialized = value_serialized

        return self.value_object

    @property
    def value(self):
        return self.value_serialized

    @value.setter
    def value(self, value):
        self.value_serialized = value

    @property
    def data(self) -> Optional[ScaleBytes]:
        """
        Returns a ScaleBytes instance of the SCALE-bytes used in the decoding process

        Returns
        -------
        bytearray
        """
        if self._data is not None:
            return ScaleBytes(self._data.data[self._data_start_offset:self._data_end_offset])

    def example_value(self):
        return self.type_def.example_value()

    def __repr__(self):

        # if self.__class__ is not ScaleType:
        #     name = self.__class__.__name__
        # else:
        #     name = self.type_def.__class__.__name__

        name = self.type_def.__class__.__name__

        if self.value_serialized is not None:
            return f"<{name}(value={self.value_serialized})>"
        elif self.data:
            return f"<{name}(data={self.data.to_hex()})>"
        else:
            return f"<{name}>"

    def __getitem__(self, item):
        return self.value_object[item]

    def __iter__(self):
        for item in self.value_object:
            yield item

    def __eq__(self, other):
        if isinstance(other, ScaleType):
            return other.value_serialized == self.value_serialized
        else:
            return other == self.value_serialized

    def __gt__(self, other):
        if isinstance(other, ScaleType):
            return self.value_serialized > other.value_serialized
        else:
            return self.value_serialized > other

    def __ge__(self, other):
        if isinstance(other, ScaleType):
            return self.value_serialized >= other.value_serialized
        else:
            return self.value_serialized >= other

    def __lt__(self, other):
        if isinstance(other, ScaleType):
            return self.value_serialized < other.value_serialized
        else:
            return self.value_serialized < other

    def __le__(self, other):
        if isinstance(other, ScaleType):
            return self.value_serialized <= other.value_serialized
        else:
            return self.value_serialized <= other


class ScalePrimitive(ScaleTypeDef):
    pass


class RegistryTypeDef(ScaleTypeDef):

    def __init__(self, portable_registry, si_type_id):
        super().__init__()
        self.portable_registry = portable_registry
        self.si_type_id = si_type_id
        self.__type_def = None

    @property
    def type_def(self) -> ScaleTypeDef:
        if self.__type_def is None:
            self.__type_def = self.portable_registry.create_scale_type_def(self.si_type_id)
            self.scale_type_cls = self.__type_def.scale_type_cls
        return self.__type_def

    def new(self, **kwargs) -> 'ScaleType':
        return self.type_def.scale_type_cls(type_def=self.type_def, **kwargs)

    def process_encode(self, value: any) -> ScaleBytes:
        return self.type_def.process_encode(value)

    def decode(self, data: ScaleBytes) -> any:
        return self.type_def.decode(data)

    def serialize(self, value: any) -> any:
        return self.type_def.serialize(value)

    def deserialize(self, value: any) -> any:
        return self.type_def.deserialize(value)

    def example_value(self, _recursion_level: int = 0, max_recursion: int = TYPE_DECOMP_MAX_RECURSIVE):
        # if _recursion_level <= 2:
        #     return self.type_def.example_value(_recursion_level + 1, max_recursion)
        # else:
        return f'<RegistryTypeDef: {self.si_type_id}>'


# class Singleton(type):
#     _instances = {}
#
#     def __call__(cls, *args, **kwargs):
#
#         if 'config_id' in kwargs:
#             instance_key = kwargs['config_id']
#         else:
#             instance_key = cls
#
#         if instance_key not in cls._instances:
#             cls._instances[instance_key] = super(Singleton, cls).__call__(*args, **kwargs)
#         return cls._instances[instance_key]
#
#
class RuntimeConfigurationObject:
    """
    Container for runtime configuration, for example type definitions and runtime upgrade information
    """

    # @classmethod
    # def all_subclasses(cls, class_):
    #     return set(class_.__subclasses__()).union(
    #         [s for c in class_.__subclasses__() for s in cls.all_subclasses(c)])

    def __init__(self, ss58_format=None):
        self.active_spec_version_id = None
        self.chain_id = None

        self.ss58_format = ss58_format

    def set_active_spec_version_id(self, spec_version_id):
        # TODO remove
        if spec_version_id != self.active_spec_version_id:
            self.active_spec_version_id = spec_version_id



#
#

#
#
# class ScaleDecoder(ABC):
#     """
#     Base class for all SCALE decoding/encoding
#     """
#
#     type_string = None
#
#     type_mapping = None
#
#     sub_type = None
#
#     runtime_config = None
#
#     def __init__(self, data: ScaleBytes, sub_type: str = None, runtime_config: RuntimeConfigurationObject = None):
#         """
#         Constructs an SCALE codec class capable of encoding and decoding SCALE-bytes
#
#         Parameters
#         ----------
#         data: ScaleBytes stream of SCALE data
#         sub_type
#         runtime_config
#         """
#         if sub_type:
#             self.sub_type = sub_type
#
#         if self.type_mapping is None and self.type_string:
#             self.build_type_mapping()
#
#         if data:
#             assert(type(data) == ScaleBytes)
#
#         if runtime_config:
#             self.runtime_config = runtime_config
#
#         if not self.runtime_config:
#             # if no runtime config is provided, fallback on singleton
#             self.runtime_config = RuntimeConfiguration()
#
#         self.data = data
#
#         self.value_object = None
#         self.value_serialized = None
#
#         self.decoded = False
#
#         self.data_start_offset = None
#         self.data_end_offset = None
#
#     @property
#     def value(self):
#         # TODO fix
#         # if not self.decoded:
#         #     self.decode()
#         return self.value_serialized
#
#     @value.setter
#     def value(self, value):
#         self.value_serialized = value
#
#     @staticmethod
#     def is_primitive(type_string: str) -> bool:
#         return type_string in ('bool', 'u8', 'u16', 'u32', 'u64', 'u128', 'u256', 'i8', 'i16', 'i32', 'i64', 'i128',
#                                'i256', 'h160', 'h256', 'h512', '[u8; 4]', '[u8; 4]', '[u8; 8]', '[u8; 16]', '[u8; 32]',
#                                '&[u8]')
#
#     @classmethod
#     def build_type_mapping(cls):
#
#         if cls.type_string and cls.type_string[0] == '(' and cls.type_string[-1] == ')':
#             type_mapping = ()
#
#             tuple_contents = cls.type_string[1:-1]
#
#             # replace subtype types
#             sub_types = re.search(r'([A-Za-z]+[<][^>]*[>])', tuple_contents)
#             if sub_types:
#                 sub_types = sub_types.groups()
#                 for sub_type in sub_types:
#                     tuple_contents = tuple_contents.replace(sub_type, sub_type.replace(',', '|'))
#
#             for tuple_element in tuple_contents.split(','):
#                 type_mapping += (tuple_element.strip().replace('|', ','),)
#
#             cls.type_mapping = type_mapping
#
#     def get_next_bytes(self, length) -> bytearray:
#         """
#         Retrieve `length` amount of bytes of the SCALE-bytes stream
#
#         Parameters
#         ----------
#         length: amount of requested bytes
#
#         Returns
#         -------
#         bytearray
#         """
#         data = self.data.get_next_bytes(length)
#         return data
#
#     def get_next_u8(self) -> int:
#         """
#         Retrieves the next byte and convert to an int
#
#         Returns
#         -------
#         int
#         """
#         return int.from_bytes(self.get_next_bytes(1), byteorder='little')
#
#     def get_next_bool(self) -> bool:
#         """
#         Retrieves the next byte and convert to an bool
#
#         Returns
#         -------
#         bool
#         """
#         data = self.get_next_bytes(1)
#         if data not in [b'\x00', b'\x01']:
#             raise InvalidScaleTypeValueException('Invalid value for datatype "bool"')
#         return data == b'\x01'
#
#     def get_remaining_bytes(self) -> bytearray:
#         """
#         Retrieves all remaining bytes from the stream
#
#         Returns
#         -------
#         bytearray
#         """
#         data = self.data.get_remaining_bytes()
#         return data
#
#     def get_used_bytes(self) -> bytearray:
#         """
#         Returns a bytearray of all SCALE-bytes used in the decoding process
#
#         Returns
#         -------
#         bytearray
#         """
#         return self.data.data[self.data_start_offset:self.data_end_offset]
#
#     @abstractmethod
#     def process(self):
#         """
#         Implementation of the decoding process
#
#         Returns
#         -------
#
#         """
#         raise NotImplementedError
#
#     def decode(self, data: ScaleBytes = None, check_remaining=True):
#         """
#         Decodes available SCALE-bytes according to type specification of this ScaleType
#
#         If no `data` is provided, it will try to decode data specified during init
#
#         If `check_remaining` is enabled, an exception will be raised when data is remaining after decoding
#
#         Parameters
#         ----------
#         data
#         check_remaining: If enabled, an exception will be raised when data is remaining after decoding
#
#         Returns
#         -------
#
#         """
#
#         if data is not None:
#             self.decoded = False
#             self.data = data
#
#         if not self.decoded:
#
#             self.data_start_offset = self.data.offset
#             self.value_serialized = self.process()
#             self.decoded = True
#
#             if self.value_object is None:
#                 # Default for value_object if not explicitly defined
#                 self.value_object = self.value_serialized
#
#             self.data_end_offset = self.data.offset
#
#             if check_remaining and self.data.offset != self.data.length:
#                 raise RemainingScaleBytesNotEmptyException(
#                     f'Decoding <{self.__class__.__name__}> - Current offset: {self.data.offset} / length: {self.data.length}'
#                 )
#
#             if self.data.offset > self.data.length:
#                 raise RemainingScaleBytesNotEmptyException(
#                     f'Decoding <{self.__class__.__name__}> - No more bytes available (needed: {self.data.offset} / total: {self.data.length})'
#                 )
#
#         return self.value
#
#     def __str__(self):
#         return str(self.serialize()) or ''
#
#     def __repr__(self):
#         return "<{}(value={})>".format(self.__class__.__name__, self.serialize())
#
#     def encode(self, value=None) -> ScaleBytes:
#         """
#         Encodes the serialized `value` representation of current `ScaleType` to a `ScaleBytes` stream
#
#         Parameters
#         ----------
#         value
#
#         Returns
#         -------
#         ScaleBytes
#         """
#
#         if value and issubclass(self.__class__, value.__class__):
#             # Accept instance of current class directly
#             self.data = value.data
#             self.value_object = value.value_object
#             self.value_serialized = value.value_serialized
#             return value.data
#
#         if value is not None:
#             self.value_serialized = value
#             self.decoded = True
#
#         self.data = self.process_encode(self.value_serialized)
#
#         if self.value_object is None:
#             self.value_object = self.value_serialized
#
#         return self.data
#
#     def process_encode(self, value) -> ScaleBytes:
#         """
#         Implementation of the encoding process
#
#         Parameters
#         ----------
#         value
#
#         Returns
#         -------
#         ScaleBytes
#         """
#         raise NotImplementedError("Encoding not implemented for this ScaleType")
#
#     @classmethod
#     def get_decoder_class(cls, type_string, data=None, runtime_config=None, **kwargs):
#         """
#         Retrieves the decoding class for provided `type_string`
#
#         Parameters
#         ----------
#         type_string
#         data
#         runtime_config
#         kwargs
#
#         Returns
#         -------
#         ScaleType
#         """
#
#         warnings.warn("Use RuntimeConfigurationObject.create_scale_object() instead", DeprecationWarning)
#
#         if not runtime_config:
#             runtime_config = RuntimeConfiguration()
#
#         decoder_class = runtime_config.get_decoder_class(
#             type_string
#         )
#         if decoder_class:
#             return decoder_class(data=data, runtime_config=runtime_config, **kwargs)
#
#         raise NotImplementedError('Decoder class for "{}" not found'.format(type_string))
#
#     # TODO rename to decode_type (confusing when encoding is introduced)
#     def process_type(self, type_string, **kwargs):
#         obj = self.runtime_config.create_scale_object(type_string, self.data, **kwargs)
#         obj.decode(check_remaining=False)
#         return obj
#
#     def serialize(self):
#         """
#         Returns a serialized representation of current ScaleType
#
#         Returns
#         -------
#
#         """
#         return self.value_serialized
#
#     @classmethod
#     def convert_type(cls, name):
#         return RuntimeConfigurationObject.convert_type_string(name)
#
#
# class RuntimeConfiguration(RuntimeConfigurationObject, metaclass=Singleton):
#     pass
#
#
# class ScaleType(ScaleDecoder, ABC):
#     """
#     Base class for all SCALE types
#     """
#     scale_info_type: 'GenericRegistryType' = None
#
#     def __init__(self, data=None, sub_type=None, metadata=None, runtime_config=None):
#         """
#
#         Initializes an `ScaleType`
#
#         Parameters
#         ----------
#         data: ScaleBytes
#         sub_type: str
#         metadata: VersionedMetadata
#         runtime_config: RuntimeConfigurationObject
#         """
#         self.metadata = metadata
#
#         # Container for meta information
#         self.meta_info: dict = {}
#
#         if not data:
#             data = ScaleBytes(bytearray())
#         super().__init__(data, sub_type, runtime_config=runtime_config)
#
#     def __getitem__(self, item):
#         return self.value_object[item]
#
#     def __iter__(self):
#         for item in self.value_object:
#             yield item
#
#     def __eq__(self, other):
#         if isinstance(other, ScaleType):
#             return other.value_serialized == self.value_serialized
#         else:
#             return other == self.value_serialized
#
#     def __gt__(self, other):
#         if isinstance(other, ScaleType):
#             return self.value_serialized > other.value_serialized
#         else:
#             return self.value_serialized > other
#
#     def __ge__(self, other):
#         if isinstance(other, ScaleType):
#             return self.value_serialized >= other.value_serialized
#         else:
#             return self.value_serialized >= other
#
#     def __lt__(self, other):
#         if isinstance(other, ScaleType):
#             return self.value_serialized < other.value_serialized
#         else:
#             return self.value_serialized < other
#
#     def __le__(self, other):
#         if isinstance(other, ScaleType):
#             return self.value_serialized <= other.value_serialized
#         else:
#             return self.value_serialized <= other
#
#     @classmethod
#     def generate_type_decomposition(cls, _recursion_level: int = 0, max_recursion: int = TYPE_DECOMP_MAX_RECURSIVE):
#         return cls.__name__
#
#
# class ScalePrimitive(ScaleType, ABC):
#     """
#     A SCALE representation of a RUST primitive
#     """
#     @classmethod
#     def generate_type_decomposition(cls, _recursion_level: int = 0, max_recursion: int = TYPE_DECOMP_MAX_RECURSIVE):
#         return cls.__name__.lower()
#
#
#
