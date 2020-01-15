#  Scale Codec
#  Copyright (C) 2019  openAware B.V.
#
#  This program is free software: you can redistribute it and/or modify
#  it under the terms of the GNU General Public License as published by
#  the Free Software Foundation, either version 3 of the License, or
#  (at your option) any later version.
#
#  This program is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#  GNU General Public License for more details.
#
#  You should have received a copy of the GNU General Public License
#  along with this program.  If not, see <http://www.gnu.org/licenses/>.
from hashlib import blake2b
from collections import OrderedDict

from scalecodec.base import ScaleDecoder, ScaleBytes
from scalecodec.metadata import MetadataDecoder
from scalecodec.types import Vec, CompactU32, Enum, Bytes, Struct, VecU8Length4
from scalecodec.utils.ss58 import ss58_decode, ss58_decode_account_index


class ExtrinsicsDecoder(ScaleDecoder):
    type_mapping = (
        ('extrinsic_length', 'Compact<u32>'),
        ('version_info', 'u8'),
        ('address', 'Address'),
        ('signature', 'Signature'),
        ('nonce', 'Compact<u32>'),
        ('era', 'Era'),
        ('call_index', '(u8,u8)'),
    )

    def __init__(self, data=None, sub_type=None, metadata: MetadataDecoder = None, address_type=42):

        assert (type(metadata) == MetadataDecoder)

        self.metadata = metadata
        self.address_type = address_type
        self.extrinsic_length = None
        self.extrinsic_hash = None
        self.version_info = None
        self.contains_transaction = False
        self.address = None
        self.signature_version = None
        self.signature = None
        self.nonce = None
        self.era = None
        self.tip = None
        self.call_index = None
        self.call_module = None
        self.call = None
        self.call_args = None
        self.params_raw = None
        self.params = []
        super().__init__(data, sub_type)

    def generate_hash(self):
        if self.contains_transaction:

            if self.extrinsic_length:
                extrinsic_data = self.data.data
            else:
                # Fallback for legacy version, prefix additional Compact<u32> with length
                extrinsic_length_type = CompactU32(ScaleBytes(bytearray()))
                extrinsic_length_type.encode(self.data.length)
                extrinsic_data = extrinsic_length_type.data.data + self.data.data

            return blake2b(extrinsic_data, digest_size=32).digest().hex()
        else:
            return None

    def process(self):
        # TODO for all attributes
        attribute_types = OrderedDict(self.type_mapping)

        self.extrinsic_length = self.process_type('Compact<u32>').value

        if self.extrinsic_length != self.data.get_remaining_length():
            # Fallback for legacy version
            self.extrinsic_length = None
            self.data.reset()

        self.version_info = self.get_next_bytes(1).hex()

        self.contains_transaction = int(self.version_info, 16) >= 80

        if self.version_info == '01' or self.version_info == '81':

            if self.contains_transaction:
                self.address = self.process_type('Address')

                self.signature = self.process_type('Signature')

                self.nonce = self.process_type(attribute_types['nonce'])

                self.era = self.process_type('Era')

                self.extrinsic_hash = self.generate_hash()

            self.call_index = self.get_next_bytes(2).hex()

        elif self.version_info == '02' or self.version_info == '82':

            if self.contains_transaction:
                self.address = self.process_type('Address')

                self.signature = self.process_type('Signature')

                self.era = self.process_type('Era')

                self.nonce = self.process_type('Compact<U64>')

                self.tip = self.process_type('Compact<Balance>')

                self.extrinsic_hash = self.generate_hash()

            self.call_index = self.get_next_bytes(2).hex()

        elif self.version_info == '03' or self.version_info == '83':

            if self.contains_transaction:
                self.address = self.process_type('Address')

                self.signature = self.process_type('Signature')

                self.era = self.process_type('Era')

                self.nonce = self.process_type('Compact<U64>')

                self.tip = self.process_type('Compact<Balance>')

                self.extrinsic_hash = self.generate_hash()

            self.call_index = self.get_next_bytes(2).hex()

        elif self.version_info == '04' or self.version_info == '84':

            if self.contains_transaction:
                self.address = self.process_type('Address')

                self.signature_version = self.process_type('U8')

                self.signature = self.process_type('Signature')

                self.era = self.process_type('Era')

                self.nonce = self.process_type('Compact<U64>')

                self.tip = self.process_type('Compact<Balance>')

                self.extrinsic_hash = self.generate_hash()

            self.call_index = self.get_next_bytes(2).hex()
        else:
            raise NotImplementedError('Extrinsics version "{}" is not implemented'.format(self.version_info))

        if self.call_index:

            self.params_raw = self.data.data[self.data.offset:]

            # Decode params

            self.call = self.metadata.call_index[self.call_index][1]
            self.call_module = self.metadata.call_index[self.call_index][0]

            if self.debug:
                print('Call: ', self.call.name)
                print('Module: ', self.call_module.name)

            for arg in self.call.args:
                if self.debug:
                    print('Param: ', arg.name, arg.type)

                arg_type_obj = self.process_type(arg.type, metadata=self.metadata)

                self.params.append({
                    'name': arg.name,
                    'type': arg.type,
                    'value': arg_type_obj.serialize(),
                    'valueRaw': arg_type_obj.raw_value
                })

        result = {
            'valueRaw': self.raw_value,
            'extrinsic_length': self.extrinsic_length,
            'version_info': self.version_info,
        }

        if self.contains_transaction:
            result['account_length'] = self.address.account_length
            result['account_id'] = self.address.account_id
            result['account_index'] = self.address.account_index
            result['account_idx'] = self.address.account_idx
            result['signature'] = self.signature.value.replace('0x', '')
            result['extrinsic_hash'] = self.extrinsic_hash
        if self.call_index:
            result['call_code'] = self.call_index
            result['call_function'] = self.call.get_identifier()
            result['call_module'] = self.call_module.get_identifier()

        if self.nonce:
            result['nonce'] = self.nonce.value

        if self.era:
            result['era'] = self.era.value

        if self.tip:
            result['tip'] = self.tip.value

        result['params'] = self.params

        return result

    def process_encode(self, value):
        # Check requirements
        if 'call_index' in value:
            self.call_index = value['call_index']

        elif 'call_module' in value and 'call_function' in value:
            # Look up call module from metadata
            for call_index, (call_module, call) in self.metadata.call_index.items():
                if call_module.name == value['call_module'] and call.name == value['call_function']:
                    self.call_index = call_index
                    self.call_module = call_module
                    self.call = call
                    break

            if not self.call_index:
                raise ValueError('Specified call module and function not found in metadata')

        elif not self.call_module or not self.call:
            raise ValueError('No call module and function specified')

        if self.contains_transaction:
            data = ScaleBytes('0x84')
            raise NotImplementedError('Encoding of signed extrinsics not supported')
        else:
            data = ScaleBytes('0x04')

        data += ScaleBytes(bytearray.fromhex(self.call_index))

        # Encode call params
        if len(self.call.args) > 0:
            for arg in self.call.args:
                if arg.name not in value.get('call_args', {}):
                    raise ValueError('Parameter \'{}\' not specified'.format(arg.name))
                else:
                    param_value = value['call_args'][arg.name]

                    arg_obj = self.get_decoder_class(arg.type, metadata=self.metadata)
                    data += arg_obj.encode(param_value)

        # Wrap payload with een length Compact<u32>
        length_obj = self.get_decoder_class('Compact<u32>')
        data = length_obj.encode(data.length) + data

        return data


class ExtrinsicsBlock61181Decoder(ExtrinsicsDecoder):
    type_mapping = (
        ('extrinsic_length', 'Compact<u32>'),
        ('version_info', 'u8'),
        ('address', 'Address'),
        ('signature', 'Signature'),
        ('nonce', 'u64'),
        ('era', 'Era'),
        ('call_index', '(u8,u8)'),
    )


class EventsDecoder(Vec):
    type_string = 'Vec<EventRecord<Event, Hash>>'

    def __init__(self, data, metadata=None, **kwargs):
        assert (not metadata or type(metadata) == MetadataDecoder)

        self.metadata = metadata
        self.elements = []

        super().__init__(data, metadata=metadata, **kwargs)

    def process(self):
        element_count = self.process_type('Compact<u32>').value

        for i in range(0, element_count):
            element = self.process_type('EventRecord', metadata=self.metadata)
            element.value['event_idx'] = i
            self.elements.append(element)

        return [e.value for e in self.elements]


class EventRecord(ScaleDecoder):

    def __init__(self, data, sub_type=None, metadata: MetadataDecoder = None):

        assert (not metadata or type(metadata) == MetadataDecoder)

        self.metadata = metadata

        self.phase = None
        self.extrinsic_idx = None
        self.type = None
        self.params = []
        self.event = None
        self.event_module = None
        self.topics = []

        super().__init__(data, sub_type)

    def process(self):

        # TODO Create option type
        self.phase = self.get_next_u8()

        if self.phase == 0:
            self.extrinsic_idx = self.process_type('U32').value

        self.type = self.get_next_bytes(2).hex()

        # Decode params

        self.event = self.metadata.event_index[self.type][1]
        self.event_module = self.metadata.event_index[self.type][0]

        for arg_type in self.event.args:
            arg_type_obj = self.process_type(arg_type)

            self.params.append({
                'type': arg_type,
                'value': arg_type_obj.serialize(),
                'valueRaw': arg_type_obj.raw_value
            })

        # Topics introduced since MetadataV5
        if self.metadata.version and self.metadata.version.index >= 5:
            self.topics = self.process_type('Vec<Hash>').value

        return {
            'phase': self.phase,
            'extrinsic_idx': self.extrinsic_idx,
            'type': self.type,
            'module_id': self.event_module.name,
            'event_id': self.event.name,
            'params': self.params,
            'topics': self.topics
        }


class Other(Bytes):
    pass


class AuthoritiesChange(Vec):
    type_string = 'Vec<AccountId>'

    def __init__(self, data, **kwargs):

        super().__init__(data, sub_type='AccountId', **kwargs)


class ConsensusEngineId(VecU8Length4):
    pass


class ChangesTrieRoot(Bytes):
    pass


class SealV0(Struct):
    type_string = '(u64, Signature)'

    type_mapping = (('slot', 'u64'), ('signature', 'Signature'))


class Consensus(Struct):
    type_string = '(ConsensusEngineId, Vec<u8>)'

    type_mapping = (('engine', 'ConsensusEngineId'), ('data', 'HexBytes'))


class Seal(Struct):
    type_string = '(ConsensusEngineId, Bytes)'

    type_mapping = (('engine', 'ConsensusEngineId'), ('data', 'HexBytes'))


class PreRuntime(Struct):
    type_string = '(ConsensusEngineId, Bytes)'

    type_mapping = (('engine', 'ConsensusEngineId'), ('data', 'HexBytes'))


class LogDigest(Enum):

    value_list = ['Other', 'AuthoritiesChange', 'ChangesTrieRoot', 'SealV0', 'Consensus', 'Seal', 'PreRuntime']

    def __init__(self, data, **kwargs):
        self.log_type = None
        self.index_value = None
        super().__init__(data, **kwargs)

    def process(self):
        self.index = int(self.get_next_bytes(1).hex())
        self.index_value = self.value_list[self.index]
        self.log_type = self.process_type(self.value_list[self.index])

        return {'type': self.log_type.type_string, 'value': self.log_type.value}

