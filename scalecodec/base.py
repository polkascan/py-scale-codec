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

from abc import abstractmethod
from typing import Optional, Union

from scalecodec.constants import TYPE_DECOMP_MAX_RECURSIVE
from scalecodec.exceptions import RemainingScaleBytesNotEmptyException, ScaleDecodeException


class ScaleBytes:
    """
    Representation of SCALE encoded Bytes.
    """

    def __init__(self, data: Union[str, bytes, bytearray, int]):
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

        if type(data) is ScaleBytes:
            return ScaleBytes(self.data + data.data)

        if type(data) is bytes:
            data = bytearray(data)
        elif type(data) == str and data[0:2] == '0x':
            data = bytearray.fromhex(data[2:])

        if type(data) is bytearray:
            return ScaleBytes(self.data + data)

    def __bytes__(self):
        return self.to_bytes()

    def to_bytes(self):
        return bytes(self.data)

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
        obj = self.scale_type_cls(type_def=self, **kwargs)
        if 'value' in kwargs:
            obj.deserialize(kwargs['value'])

        if 'scale' in kwargs:
            obj.decode(kwargs['scale'])

        return obj

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
    def _encode(self, value: any) -> ScaleBytes:
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
        return self._encode(value)

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

    def __init__(self, type_def: ScaleTypeDef, **kwargs):
        # TODO remove kwargs

        self.meta_info = None
        self.type_def: ScaleTypeDef = type_def
        self.value_serialized = None
        self.value_object = None

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

        if check_remaining and self._data_end_offset != self._data.length:
            raise ScaleDecodeException(
                f'Remaining ScaleBytes - Current offset: {self._data_end_offset} / length: {self._data.length}'
            )

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
        self.value_serialized = self.type_def.serialize(self.value_object)

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
