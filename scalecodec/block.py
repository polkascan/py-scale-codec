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
            'attributes': self.value_object[1][1].value,
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
            'extrinsic_idx': self.value_object['phase'][1].value,
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
                self.authority_index = babe_predigest_value['authorityIndex']
                self.slot_number = babe_predigest_value['slotNumber']

        if value['engine'] == 'aura':

            aura_predigest = self.runtime_config.create_scale_object(
                type_string='RawAuraPreDigest',
                data=ScaleBytes(bytearray.fromhex(value['data'].replace('0x', '')))
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

