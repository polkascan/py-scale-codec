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

    def encode(self, value: int):

        if value <= 0b00111111:
            self.data = ScaleBytes(bytearray(int(value << 2).to_bytes(1, 'little')))

        elif value <= 0b0011111111111111:
            self.data = ScaleBytes(bytearray(int((value << 2) | 0b01).to_bytes(2, 'little')))

        elif value <= 0b00111111111111111111111111111111:

            self.data = ScaleBytes(bytearray(int((value << 2) | 0b10).to_bytes(4, 'little')))

        else:
            raise NotImplemented('Value range not implemented')

        return self.data


class Option(ScaleType):
    def process(self):

        option_byte = self.get_next_bytes(1)

        if self.sub_type and option_byte != b'\x00':
            return self.process_type(self.sub_type).value

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

    type_mapping = (('unstakeThreshold', 'Compact<u32>'), ('validatorPayment', 'Compact<Balance>'))


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


class BalanceOf(Balance):
    pass


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


class RawAddress(Address):
    pass


class Enum(ScaleType):

    value_list = []

    def __init__(self, data, value_list=None, **kwargs):

        self.index = None

        if value_list:
            self.value_list = value_list
        super().__init__(data, **kwargs)

    def process(self):
        self.index = int(self.get_next_bytes(1).hex())
        try:
            return self.value_list[self.index]
        except IndexError:
            raise ValueError("Index '{}' not present in Enum value list".format(self.index))


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


class ProposalIndex(U32):
    pass


class Permill(U32):
    pass


class StorageHasher(Enum):

    value_list = ['Blake2_128', 'Blake2_256', 'Twox128', 'Twox256', 'Twox128Concat']

    def is_blake2_128(self):
        return self.index == 0

    def is_blake2_256(self):
        return self.index == 1

    def is_twox128(self):
        return self.index == 2

    def is_twox256(self):
        return self.index == 3

    def is_twox128_concat(self):
        return self.index == 4


class Gas(U64):
    pass


class CodeHash(Hash):
    pass


# Edgeware types
# TODO move to RuntimeConfiguration per network

class IdentityType(Bytes):
    pass


class VoteType(Enum):

    type_string = 'voting::VoteType'

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


class VoteStage(Enum):
    value_list = ['PreVoting', 'Commit', 'Voting', 'Completed']


class TallyType(Enum):

    type_string = 'voting::TallyType'

    value_list = ['OnePerson', 'OneCoin']


class Attestation(Bytes):
    pass


# Joystream types
# TODO move to RuntimeConfiguration per network

class ContentId(H256):
    pass


class MemberId(U64):
    pass


class PaidTermId(U64):
    pass


class SubscriptionId(U64):
    pass


class SchemaId(U64):
    pass


class DownloadSessionId(U64):
    pass


class UserInfo(Struct):

    type_mapping = (
        ('handle', 'Option<Vec<u8>>'),
        ('avatar_uri', 'Option<Vec<u8>>'),
        ('about', 'Option<Vec<u8>>')
    )


class Role(Enum):

    value_list = ['Storage']


class ContentVisibility(Enum):
    value_list = ['Draft', 'Public']


class ContentMetadata(Struct):
    type_mapping = (
        ('owner', 'AccountId'),
        ('added_at', 'BlockAndTime'),
        ('children_ids', 'Vec<ContentId>'),
        ('visibility', 'ContentVisibility'),
        ('schema', 'SchemaId'),
        ('json', 'Vec<u8>'),

    )


class ContentMetadataUpdate(Struct):
    type_mapping = (
        ('children_ids', 'Option<Vec<ContentId>>'),
        ('visibility', 'Option<ContentVisibility>'),
        ('schema', 'Option<SchemaId>'),
        ('json', 'Option<Vec<u8>>')
    )


class LiaisonJudgement(Enum):
    value_list = ['Pending', 'Accepted', 'Rejected']


class BlockAndTime(Struct):
    type_mapping = (
        ('block', 'BlockNumber'),
        ('time', 'Moment')
    )


class DataObjectTypeId(U64):
    type_string = "<T as DOTRTrait>::DataObjectTypeId"


class DataObject(Struct):
    type_mapping = (
        ('owner', 'AccountId'),
        ('added_at', 'BlockAndTime'),
        ('type_id', 'DataObjectTypeId'),
        ('size', 'u64'),
        ('liaison', 'AccountId'),
        ('liaison_judgement', 'LiaisonJudgement'),
    )


class DataObjectStorageRelationshipId(U64):
    pass


class ProposalStatus(Enum):
    value_list = ['Active', 'Cancelled', 'Expired', 'Approved', 'Rejected', 'Slashed']


class VoteKind(Enum):
    value_list = ['Abstain', 'Approve', 'Reject', 'Slash']


class TallyResult(Struct):
    type_string = 'TallyResult<BlockNumber>'

    type_mapping = (
        ('proposal_id', 'u32'),
        ('abstentions', 'u32'),
        ('approvals', 'u32'),
        ('rejections', 'u32'),
        ('slashes', 'u32'),
        ('status', 'ProposalStatus'),
        ('finalized_at', 'BlockNumber'),
    )


# Robonomics types
# TODO move to RuntimeConfiguration per network

class Order(Struct):
    type_string = 'Order<Balance, AccountId>'

    type_mapping = (
        ('models', 'Vec<u8>'),
        ('objective', 'Vec<u8>'),
        ('cost', 'Balance'),
        ('custodian', 'AccountId'),
    )


class Offer(Struct):
    type_string = 'Offer<Balance, AccountId>'

    type_mapping = (
        ('order', 'Order<Balance, AccountId>'),
        #('sender', 'AccountId'),
    )


class Demand(Struct):
    type_string = 'Demand<Balance, AccountId>'

    type_mapping = (
        ('order', 'Order<Balance, AccountId>'),
        #('sender', 'AccountId'), TODO not present in current blocks but referenced in https://github.com/airalab/substrate-node-robonomics/blob/master/res/custom_types.json
    )


class Liability(Struct):
    type_string = 'Liability<Balance, AccountId>'

    type_mapping = (
        ('order', 'Order<Balance, AccountId>'),
        ('promisee', 'AccountId'),
        #('promisor', 'AccountId'), TODO not present in current blocks but referenced in https://github.com/airalab/substrate-node-robonomics/blob/master/res/custom_types.json
        ('result', 'Option<Vec<u8>>'),
    )


class LiabilityIndex(U64):
    pass
