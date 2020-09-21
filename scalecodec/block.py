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
from hashlib import blake2b
from collections import OrderedDict

from scalecodec.base import ScaleDecoder, ScaleBytes
from scalecodec.types import FixedLengthArray
from scalecodec.metadata import MetadataDecoder
from scalecodec.types import Vec, CompactU32, Enum, Bytes, Struct
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
            return blake2b(self.data.data, digest_size=32).digest().hex()

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

                self.signature = self.process_type('Signature').value

                self.nonce = self.process_type(attribute_types['nonce'])

                self.era = self.process_type('Era')

                self.extrinsic_hash = self.generate_hash()

            self.call_index = self.get_next_bytes(2).hex()

        elif self.version_info == '02' or self.version_info == '82':

            if self.contains_transaction:
                self.address = self.process_type('Address')

                self.signature = self.process_type('Signature').value

                self.era = self.process_type('Era')

                self.nonce = self.process_type('Compact<Index>')

                self.tip = self.process_type('Compact<Balance>')

                self.extrinsic_hash = self.generate_hash()

            self.call_index = self.get_next_bytes(2).hex()

        elif self.version_info == '03' or self.version_info == '83':

            if self.contains_transaction:
                self.address = self.process_type('Address')

                self.signature = self.process_type('Signature').value

                self.era = self.process_type('Era')

                self.nonce = self.process_type('Compact<Index>')

                self.tip = self.process_type('Compact<Balance>')

                self.extrinsic_hash = self.generate_hash()

            self.call_index = self.get_next_bytes(2).hex()

        elif self.version_info == '04' or self.version_info == '84':

            if self.contains_transaction:
                self.address = self.process_type('Address')

                multi_signature = self.process_type("MultiSignature")

                self.signature_version = multi_signature.index

                self.signature = multi_signature.get_enum_value()

                self.era = self.process_type('Era')

                self.nonce = self.process_type('Compact<Index>')

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

            for arg in self.call.args:

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
            result['signature_version'] = self.signature_version
            result['signature'] = self.signature.replace('0x', '')
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

        if 'call_index' in value:
            self.call_index = value['call_index']

        elif 'call_module' in value and 'call_function' in value:
            # Look up call module from metadata
            for call_index, (call_module, call) in self.metadata.call_index.items():
                if call_module.name.lower() == value['call_module'].lower() and call.name == value['call_function']:
                    self.call_index = call_index
                    self.call_module = call_module
                    self.call = call
                    break

            if not self.call_index:
                raise ValueError('Specified call module and function not found in metadata')

        elif not self.call_module or not self.call:
            raise ValueError('No call module and function specified')

        # Determine version (Fixed to V4 for now)
        if 'account_id' in value:
            self.version_info = '84'
            self.contains_transaction = True
        else:
            self.version_info = '04'
            self.contains_transaction = False

        if self.contains_transaction:
            data = ScaleBytes('0x84')

            self.address = self.get_decoder_class('Address', metadata=self.metadata)
            data += self.address.encode(value['account_id'])

            self.signature_version = self.get_decoder_class('U8', metadata=self.metadata)
            data += self.signature_version.encode(value['signature_version'])

            self.signature = self.get_decoder_class('Signature', metadata=self.metadata)
            data += self.signature.encode('0x{}'.format(value['signature'].replace('0x', '')))

            self.era = self.get_decoder_class('Era', metadata=self.metadata)
            data += self.era.encode(value['era'])

            self.nonce = self.get_decoder_class('Compact<Index>', metadata=self.metadata)
            data += self.nonce.encode(value['nonce'])

            self.tip = self.get_decoder_class('Compact<Balance>', metadata=self.metadata)
            data += self.tip.encode(value['tip'])

        else:
            data = ScaleBytes('0x04')

        data += ScaleBytes(bytearray.fromhex(self.call_index))

        # Convert params to call_args TODO refactor
        if not value.get('call_args') and value.get('params'):
            value['call_args'] = {call_arg['name']: call_arg['value'] for call_arg in value.get('params')}

        # Encode call params
        if len(self.call.args) > 0:
            for arg in self.call.args:
                if arg.name not in value.get('call_args', {}):
                    raise ValueError('Parameter \'{}\' not specified'.format(arg.name))
                else:
                    param_value = value['call_args'][arg.name]

                    arg_obj = self.get_decoder_class(arg.type, metadata=self.metadata)
                    data += arg_obj.encode(param_value)

        # Wrap payload with a length Compact<u32>
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


class GenericEvent(ScaleDecoder):

    def __init__(self, data, sub_type=None, metadata: MetadataDecoder = None):

        assert (not metadata or type(metadata) == MetadataDecoder)

        self.metadata = metadata

        self.extrinsic_idx = None
        self.type = None
        self.params = []
        self.event = None
        self.event_module = None

        super().__init__(data, sub_type)

    def process(self):

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

        return {
            'extrinsic_idx': self.extrinsic_idx,
            'type': self.type,
            'module_id': self.event_module.name,
            'event_id': self.event.name,
            'params': self.params,
        }


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


class GenericConsensusEngineId(FixedLengthArray):
    sub_type = 'u8'
    element_count = 4

    def process(self):
        return self.get_next_bytes(self.element_count).decode()


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

