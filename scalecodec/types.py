# Python SCALE Codec Library
#
# Copyright 2018-2019 openAware BV (NL).
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

from datetime import datetime
from scalecodec.base import ScaleType, ScaleBytes


class Compact(ScaleType):

    def __init__(self, data, **kwargs):
        self.compact_length = 0
        self.compact_bytes = None
        super().__init__(data, **kwargs)

    def process_compact_bytes(self):
        compact_byte = self.get_next_bytes(1)

        byte_mod = compact_byte[0] % 4

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

            # TODO Assumptions
            if type(byte_data) is int and self.compact_length <= 4:
                return int(byte_data / 4)
            else:
                # TODO raise exception?
                return byte_data
        else:
            return self.compact_bytes


# Example of specialized composite implementation for performance improvement
class CompactU32(Compact):

    type_string = 'Compact<u32>'

    def process(self):
        self.process_compact_bytes()

        if self.compact_length <= 4:
            return int(int.from_bytes(self.compact_bytes, byteorder='little') / 4)
        else:
            return int.from_bytes(self.compact_bytes, byteorder='little')


class Option(ScaleType):
    def process(self):

        option_byte = self.get_next_bytes(1)

        if self.sub_type and option_byte != b'\x00':
            self.data.reset()
            return self.get_decoder_class(self.sub_type, ScaleBytes(self.data)).process()

        return None


class Bytes(ScaleType):

    type_string = 'Vec<u8>'

    def process(self):

        length = self.process_type('Compact<u32>').value
        value = self.get_next_bytes(length)

        try:
            return value.decode()
        except UnicodeDecodeError:
            return value.hex()


# TODO replace in metadata
class String(ScaleType):

    def process(self):

        length = self.process_type('Compact<u32>').value
        value = self.get_next_bytes(length)

        return value.decode()


class HexBytes(ScaleType):

    def process(self):

        length = self.process_type('Compact<u32>').value

        return '0x{}'.format(self.get_next_bytes(length).hex())


class U8(ScaleType):

    def process(self):
        return self.get_next_u8()


class U32(ScaleType):

    def process(self):
        return int.from_bytes(self.get_next_bytes(4), byteorder='little')


class U64(ScaleType):

    def process(self):
        return int(int.from_bytes(self.get_next_bytes(8), byteorder='little'))


class U128(ScaleType):

    def process(self):
        return int(int.from_bytes(self.get_next_bytes(16), byteorder='little'))


class H256(ScaleType):

    def process(self):
        return '0x{}'.format(self.get_next_bytes(32).hex())


class Era(ScaleType):

    def process(self):

        option_byte = self.get_next_bytes(1).hex()
        if option_byte == '00':
            return option_byte
        else:
            return option_byte + self.get_next_bytes(1).hex()


class Bool(ScaleType):

    def process(self):
        return self.get_next_bool()


class Moment(CompactU32):
    type_string = 'Compact<Moment>'

    def process(self):
        int_value = super().process()
        return datetime.utcfromtimestamp(int_value)

    def serialize(self):
        return self.value.isoformat()


class BoxProposal(ScaleType):
    type_string = 'Box<Proposal>'

    def __init__(self, data, **kwargs):
        self.call_index = None
        self.call = None
        self.call_module = None
        self.params = []
        super().__init__(data, **kwargs)

    def process(self):

        self.call_index = self.get_next_bytes(2).hex()

        self.call_module, self.call = self.metadata.call_index[self.call_index]

        for arg in self.call.args:
            arg_type_obj = self.process_type(arg.type, metadata=self.metadata)

            self.params.append({
                'name': arg.name,
                'type': arg.type,
                'value': arg_type_obj.serialize(),
                'valueRaw': arg_type_obj.raw_value
            })

        return {
            'call_index': self.call_index,
            'call_name': self.call.name,
            'call_module': self.call_module.name,
            'params': self.params
        }


class Struct(ScaleType):
    type_mapping = {}

    def process(self):

        result = {}

        for key, data_type in self.type_mapping:
            result[key] = self.process_type(data_type).value

        return result


class ValidatorPrefs(Struct):

    type_string = '(Compact<u32>,Compact<Balance>)'

    type_mapping = (('col1', 'Compact<u32>'), ('col2', 'Compact<Balance>'))


class AccountId(H256):
    pass


class AccountIndex(U32):
    pass


class ReferendumIndex(U32):
    pass


class PropIndex(U32):
    pass


class Vote(U8):
    pass


class SessionKey(H256):
    pass


class AttestedCandidate(H256):
    pass


class Balance(U128):
    pass


class ParaId(U32):
    pass


class Key(Bytes):
    pass


class KeyValue(Struct):
    type_string = '(Vec<u8>, Vec<u8>)'
    type_mapping = (('key', 'Vec<u8>'), ('value', 'Vec<u8>'))


class Signature(ScaleType):

    def process(self):
        return self.get_next_bytes(64).hex()


class BalanceOf(CompactU32):

    type_string = 'Compact<BalanceOf>'


class BlockNumber(U64):
    pass


class NewAccountOutcome(CompactU32):
    pass


class Vec(ScaleType):

    def __init__(self, data, **kwargs):
        self.elements = []
        super().__init__(data, **kwargs)

    def process(self):
        element_count = self.process_type('Compact<u32>').value

        result = []
        for _ in range(0, element_count):
            element = self.process_type(self.sub_type)
            self.elements.append(element)
            result.append(element.value)

        return result

# class BalanceTransferExtrinsic(Decoder):
#
#     type_string = '(Address,Compact<Balance>)'
#
#     type_mapping = {'to': 'Address', 'balance': 'Compact<Balance>'}


class Address(ScaleType):

    def __init__(self, data, **kwargs):
        self.account_length = None
        self.account_id = None
        self.account_index = None
        super().__init__(data, **kwargs)

    def process(self):
        self.account_length = self.get_next_bytes(1).hex()

        if self.account_length == 'ff':
            self.account_id = self.get_next_bytes(32).hex()
            return self.account_id
        else:
            if self.account_length == 'fc':
                self.account_index = self.get_next_bytes(2).hex()
            elif self.account_length == 'fd':
                self.account_index = self.get_next_bytes(4).hex()
            elif self.account_length == 'fe':
                self.account_index = self.get_next_bytes(8).hex()
            else:
                self.account_index = self.account_length

            return self.account_index


class RawAddress(Address):
    pass


class Enum(ScaleType):

    value_list = []

    def __init__(self, data, value_list=None, **kwargs):
        if value_list:
            self.value_list = value_list
        super().__init__(data, **kwargs)

    def process(self):
        index = int(self.get_next_bytes(1).hex())
        try:
            return self.value_list[index]
        except IndexError:
            raise ValueError("Index '{}' not present in Enum value list".format(index))


class RewardDestination(Enum):

    value_list = ['Staked', 'Stash', 'Controller']


class VoteThreshold(Enum):

    value_list = ['SuperMajorityApprove', 'SuperMajorityAgainst', 'SimpleMajority']


class Inherent(Bytes):
    pass


class LockPeriods(U8):
    pass


class Hash(H256):
    pass


class VoteIndex(U32):
    pass


class IdentityType(Bytes):
    pass


class VoteType(Enum):
    value_list = ['Binary', 'MultiOption']


class VoteOutcome(ScaleType):

    def process(self):
        return list(self.get_next_bytes(32))


class Identity(Bytes):
    pass


class ProposalTitle(Bytes):
    pass


class ProposalContents(Bytes):
    pass


class ProposalStage(Enum):
    value_list = ['PreVoting', 'Voting', 'Completed']


class ProposalCategory(Enum):
    value_list = ['Signaling']
