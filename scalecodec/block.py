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
import warnings
from hashlib import blake2b
from collections import OrderedDict

from scalecodec.base import ScaleDecoder, ScaleBytes, ScaleType
from scalecodec.types import FixedLengthArray
from scalecodec.types import Vec, Enum, Bytes, Struct


class OpaqueExtrinsic(Struct):
    type_mapping = (
        ('length', 'Compact<u32>'),
        ('extrinsic', 'ExtrinsicVersioned')
    )

    def extract_extrinsic(self):
        pass

    def process(self):
        return super().process()


class ExtrinsicVersioned(Enum):
    type_mapping = (
        ('InherentV0', 'InherentV0'),
        ('InherentV1', 'InherentV1'),
        ('InherentV2', 'InherentV2'),
        ('InherentV3', 'InherentV3'),
        ('InherentV4', 'InherentV4'),
        ('ExtrinsicV0', 'ExtrinsicV0'),
        ('ExtrinsicV1', 'ExtrinsicV1'),
        ('ExtrinsicV2', 'ExtrinsicV2'),
        ('ExtrinsicV3', 'ExtrinsicV3'),
        ('ExtrinsicV4', 'ExtrinsicV4')
    )

    def process(self):
        return super().process()


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
        if self.signed:
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
                'call_function': value['call_function'],
                'call_module': value['call_module'],
                'call_args': value['call_args'],
            }

        # Determine version (Fixed to V4 for now)
        if 'address' in value:
            data = ScaleBytes('0x84')
            self.signed = True
        else:
            data = ScaleBytes('0x04')
            self.signed = False

        if self.signed:
            extrinsic = self.get_decoder_class('ExtrinsicV4', runtime_config=self.runtime_config, metadata=self.metadata)
            data += extrinsic.encode(value)

        # Wrap payload with a length Compact<u32>
        length_obj = self.get_decoder_class('Compact<u32>', runtime_config=self.runtime_config)
        data = length_obj.encode(data.length) + data

        return data


class Extrinsic(GenericExtrinsic):
    type_mapping = (
        ('extrinsic_length', 'Compact<u32>'),
        ('version_info', 'u8'),
        ('address', 'Address'),
        ('signature', 'Signature'),
        ('nonce', 'Compact<u32>'),
        ('era', 'Era'),
        ('call_index', '(u8,u8)'),
    )

    def __init__(self, *args, address_type=42, **kwargs):

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

        super().__init__(*args, **kwargs)

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
                    'value': arg_type_obj.serialize()
                })

        result = {
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
            result['call_index'] = self.call_index
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

            self.address = self.get_decoder_class('Address', metadata=self.metadata, runtime_config=self.runtime_config)
            data += self.address.encode(value['account_id'])

            self.signature_version = self.get_decoder_class(
                'U8', metadata=self.metadata, runtime_config=self.runtime_config
            )
            data += self.signature_version.encode(value['signature_version'])

            self.signature = self.get_decoder_class(
                'Signature', metadata=self.metadata, runtime_config=self.runtime_config
            )
            data += self.signature.encode('0x{}'.format(value['signature'].replace('0x', '')))

            self.era = self.get_decoder_class('Era', metadata=self.metadata, runtime_config=self.runtime_config)
            data += self.era.encode(value['era'])

            self.nonce = self.get_decoder_class(
                'Compact<Index>', metadata=self.metadata, runtime_config=self.runtime_config
            )
            data += self.nonce.encode(value['nonce'])

            self.tip = self.get_decoder_class(
                'Compact<Balance>', metadata=self.metadata, runtime_config=self.runtime_config
            )
            data += self.tip.encode(value['tip'])

        else:
            data = ScaleBytes('0x04')

        data += ScaleBytes(bytearray.fromhex(self.call_index))

        if not value.get('call_args') and value.get('params'):
            value['call_args'] = {call_arg['name']: call_arg['value'] for call_arg in value.get('params')}

        # Encode call params
        if len(self.call.args) > 0:
            for arg in self.call.args:
                if arg.name not in value.get('call_args', {}):
                    raise ValueError('Parameter \'{}\' not specified'.format(arg.name))
                else:
                    param_value = value['call_args'][arg.name]

                    arg_obj = self.get_decoder_class(
                        type_string=arg.type, metadata=self.metadata, runtime_config=self.runtime_config
                    )
                    data += arg_obj.encode(param_value)

        # Wrap payload with a length Compact<u32>
        length_obj = self.get_decoder_class('Compact<u32>', runtime_config=self.runtime_config)
        data = length_obj.encode(data.length) + data

        return data

    def __repr__(self):
        return "<{}(value={})>".format(self.__class__.__name__, self.value)


# TODO deprecated
class ExtrinsicsDecoder(Extrinsic):

    def __init__(self, *args, **kwargs):
        warnings.warn("ExtrinsicsDecoder will be removed in the future", DeprecationWarning)
        super().__init__(*args, **kwargs)


# TODO deprecated
class EventsDecoder(Vec):
    type_string = 'Vec<EventRecord<Event, Hash>>'

    def __init__(self, data, metadata=None, **kwargs):
        warnings.warn("EventsDecoder will be removed in the future", DeprecationWarning)

        if metadata and metadata.__class__.__name__ not in ['MetadataDecoder', 'MetadataVersioned']:
            raise ValueError("metadata not correct")

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
            'event_id': self.value_object[1].value_object[0],
            'attributes': self.value_object[1].value_object[1].value,
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

        return {
            'phase': self.value_object['phase'].index,
            'extrinsic_idx': self.value_object['phase'].value_object[1].value,
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
            babe_predigest = self.get_decoder_class(
                type_string='RawBabePreDigest',
                data=ScaleBytes(bytearray.fromhex(value['data'].replace('0x', ''))),
                runtime_config=self.runtime_config
            )

            babe_predigest.decode()

            if len(list(babe_predigest.value.values())) > 0:
                babe_predigest_value = list(babe_predigest.value.values())[0]

                value['data'] = babe_predigest_value
                self.authority_index = babe_predigest_value['authorityIndex']
                self.slot_number = babe_predigest_value['slotNumber']

        if value['engine'] == 'aura':

            aura_predigest = self.get_decoder_class(
                type_string='RawAuraPreDigest',
                data=ScaleBytes(bytearray.fromhex(value['data'].replace('0x', ''))),
                runtime_config=self.runtime_config
            )
            aura_predigest.decode()

            value['data'] = aura_predigest.value
            self.slot_number = aura_predigest.value['slotNumber']

        return value


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

        return {'type': self.value_list[self.index], 'value': self.log_type.value}

