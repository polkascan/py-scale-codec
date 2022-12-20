# Python SCALE Codec

[![Build Status](https://img.shields.io/github/actions/workflow/status/polkascan/py-scale-codec/unittests.yml?branch=master)](https://github.com/polkascan/py-scale-codec/actions/workflows/unittests.yml?query=workflow%3A%22Run+unit+tests%22)
[![Latest Version](https://img.shields.io/pypi/v/scalecodec.svg)](https://pypi.org/project/scalecodec/) 
[![Supported Python versions](https://img.shields.io/pypi/pyversions/scalecodec.svg)](https://pypi.org/project/scalecodec/)
[![License](https://img.shields.io/pypi/l/scalecodec.svg)](https://github.com/polkascan/py-scale-codec/blob/master/LICENSE)


## Description
[Substrate](https://github.com/paritytech/substrate) uses a lightweight and efficient [encoding and decoding program](https://docs.substrate.io/reference/scale-codec/) to optimize how data is sent and received over the network. The program used to serialize and deserialize data is called the SCALE codec, with SCALE being an acronym for **S**imple **C**oncatenated **A**ggregate **L**ittle-**E**ndian.

## Installation
```bash
pip install scalecodec
```

## API reference documentation
https://polkascan.github.io/py-scale-codec/

## Examples of different types

| Type                                                                         | Description                                                                                                                                                                                                                                                                                                                                                                                                                                                                          | Example SCALE decoding value                                                | SCALE encoded value                                                             |
|------------------------------------------------------------------------------|--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|-----------------------------------------------------------------------------|---------------------------------------------------------------------------------|
| `bool`                                                                       | Boolean values are encoded using the least significant bit of a single byte.                                                                                                                                                                                                                                                                                                                                                                                                         | `True`                                                                      | `0x01`                                                                          |
| `u16`                                                                        | Basic integers are encoded using a fixed-width little-endian (LE) format.                                                                                                                                                                                                                                                                                                                                                                                                            | `42`                                                                        | `0x2a00`                                                                        |
| `Compact`                                                                    | A "compact" or general integer encoding is sufficient for encoding large integers (up to 2**536) and is more efficient at encoding most values than the fixed-width version. (Though for single-byte values, the fixed-width integer is never worse.)                                                                                                                                                                                                                                | `0`                                                                         | `0x00`                                                                          |
|                                                                              |                                                                                                                                                                                                                                                                                                                                                                                                                                                                                      | `1`                                                                         | `0x04`                                                                          |
|                                                                              |                                                                                                                                                                                                                                                                                                                                                                                                                                                                                      | `42`                                                                        | `0xa8`                                                                          |
|                                                                              |                                                                                                                                                                                                                                                                                                                                                                                                                                                                                      | `69`                                                                        | `0x1501`                                                                        |
|                                                                              |                                                                                                                                                                                                                                                                                                                                                                                                                                                                                      | `100000000000000`                                                           | `0x0b00407a10f35a`                                                              |
| `Vec`                                                                        | A collection of same-typed values is encoded, prefixed with a compact encoding of the number of items, followed by each item's encoding concatenated in turn.                                                                                                                                                                                                                                                                                                                        | `[4, 8, 15, 16, 23, 42]`                                                    | `0x18040008000f00100017002a00`                                                  |
| `BitVec`                                                                     | A sequence of bools, represented in a more space efficient bit format                                                                                                                                                                                                                                                                                                                                                                                                             | `0b00000010_01111101`                                                    | `0x287d02`                                                  |
| `str`,`Bytes`, `String`                                                      | Strings are Vectors of bytes (`Vec<u8>`) containing a valid UTF8 sequence.                                                                                                                                                                                                                                                                                                                                                                                                           | `"Test"`                                                                    | `0x1054657374`                                                                  |
|                                                                              |                                                                                                                                                                                                                                                                                                                                                                                                                                                                                      | `b"Test"`                                                                   | `0x1054657374`                                                                  |
|                                                                              |                                                                                                                                                                                                                                                                                                                                                                                                                                                                                      | `[84, 101, 115, 116]`                                                       | `0x1054657374`                                                                  |
| `[u8; 4]`                                                                    | Fixed sized array of in this case an `u8`                                                                                                                                                                                                                                                                                                                                                                                                                                            | `b"babe"`                                                                   | `0x62616265`                                                                    |
|                                                                              |                                                                                                                                                                                                                                                                                                                                                                                                                                                                                      | `"0x62616265"`                                                              | `0x62616265`                                                                    |
|                                                                              |                                                                                                                                                                                                                                                                                                                                                                                                                                                                                      | `[98, 97, 98, 101]`                                                         | `0x62616265`                                                                    |
| `AccountId`                                                                  | An [SS58 formatted](https://docs.substrate.io/reference/address-formats/) representation of an account. See also the [SS58 util functions](https://polkascan.github.io/py-scale-codec/utils/ss58.html)                                                                                                                                                                                                                                                                               | `"5GDyPHLVHcQYPTWfygtPY eogQjyZy7J9fsi4brPhgEFq4pcv"`                       | `0xb80269ec500e458a630846b99105c397 ee574125823d6f4388e9c7572e115c05`           |
| `Enum` Example: `enum IntOrBool { Int(u8), Bool(bool),}`                     | A fixed number of variants, each mutually exclusive and potentially implying a further value or series of values. Encoded as the first byte identifying the index of the variant that the value is. Any further bytes are used to encode any data that the variant implies. Thus, no more than 256 variants are supported.                                                                                                                                                           | `{'Int': 8}`                                                                | `0x002a`                                                                        |
|                                                                              |                                                                                                                                                                                                                                                                                                                                                                                                                                                                                      | `{'Bool': True}`                                                            | `0x0101`                                                                        |
| `Struct` Example: `struct Motion { pub votes: Vec<AccountId>, pub id: u32 }` | For structures, the values are named, but that is irrelevant for the encoding (names are ignored - only order matters). All containers store elements consecutively. The order of the elements is not fixed, depends on the container, and cannot be relied on at decoding. This implicitly means that decoding some byte-array into a specified structure that enforces an order and then re-encoding it could result in a different byte array than the original that was decoded. | `{"votes": ["5GDyPHLVHcQYPTWfygtPYeo gQjyZy7J9fsi4brPhgEFq4pcv"], "id": 4}` | `0x04b80269ec500e458a630846b99105c397ee57 4125823d6f4388e9c7572e115c0504000000` |


## Code Examples

### Encode a Call

```python

runtime_config = RuntimeConfigurationObject()
# This types are all hardcoded types needed to decode metadata types
runtime_config.update_type_registry(load_type_registry_preset(name="core"))

# Decode retrieved metadata from the RPC
metadata = runtime_config.create_scale_object(
    'MetadataVersioned', data=ScaleBytes(response.get('result'))
)
metadata.decode()

# Add the embedded type registry to the runtime config
runtime_config.add_portable_registry(metadata)

call = runtime_config.create_scale_object(
    "Call", metadata=metadata
)
call.encode({
    "call_module": "Balances",
    "call_function": "transfer",
    "call_args": {"dest": "5GNJqTPyNqANBkUVMN1LPPrxXnFouWXoe2wNSmmEoLctxiZY", "value": 3},
})
```

### Decode the result of a `state_getStorageAt` RPC call

```python
event_data = "0x2000000000000000b0338609000000000200000001000000000080b2e60e0000000002000000020000000003be1957935299d0be2f35b8856751feab95fc7089239366b52b72ca98249b94300000020000000500be1957935299d0be2f35b8856751feab95fc7089239366b52b72ca98249b943000264d2823000000000000000000000000000200000005027a9650a6bd43f1e0b4546affb88f8c14213e1fb60512692c2b39fbfcfc56b703be1957935299d0be2f35b8856751feab95fc7089239366b52b72ca98249b943000264d2823000000000000000000000000000200000013060c4c700700000000000000000000000000000200000005047b8441d5110c178c29be709793a41d73ae8b3119a971b18fbd20945ea5d622f00313dc01000000000000000000000000000002000000000010016b0b00000000000000"

system_pallet = metadata.get_metadata_pallet("System")
event_storage_function = system_pallet.get_storage_function("Events")

event = runtime_config.create_scale_object(
    event_storage_function.get_value_type_string(), metadata=metadata
)
print(event.decode(ScaleBytes(event_data)))
```

### Generate type decomposition information

The function `generate_type_decomposition` can be 
used when more information is needed how to encode a certain SCALE type:  

_Example 1_
```python
scale_obj = runtime_config.create_scale_object("RawBabePreDigest")

type_info = scale_obj.generate_type_decomposition()

print(type_info)
# {
#   'Phantom': None, 
#   'Primary': {'authority_index': 'u32', 'slot_number': 'u64', 'vrf_output': '[u8; 32]', 'vrf_proof': '[u8; 64]'}, 
#   'SecondaryPlain': {'authority_index': 'u32', 'slot_number': 'u64'}, 
#   'SecondaryVRF': {'authority_index': 'u32', 'slot_number': 'u64', 'vrf_output': '[u8; 32]', 'vrf_proof': '[u8; 64]'}
# }
```

_Example 2_
```python
pallet = metadata.get_metadata_pallet("Tokens")
storage_function = pallet.get_storage_function("TotalIssuance")

param_type_string = storage_function.get_params_type_string()
param_type_obj = runtime_config.create_scale_object(param_type_string[0])

type_info = param_type_obj.generate_type_decomposition()

print(type_info)
# [{
#   'Token': ('ACA', 'AUSD', 'DOT', 'LDOT', 'RENBTC', 'CASH', 'KAR', 'KUSD', 'KSM', 'LKSM', 'TAI', 'BNC', 'VSKSM', 'PHA', 'KINT', 'KBTC'), 
#   'DexShare': ({'Token': ('ACA', 'AUSD', 'DOT', 'LDOT', 'RENBTC', 'CASH', 'KAR', 'KUSD', 'KSM', 'LKSM', 'TAI', 'BNC', 'VSKSM', 'PHA', 'KINT', 'KBTC'), 'Erc20': '[u8; 20]', 'LiquidCrowdloan': 'u32', 'ForeignAsset': 'u16'}, {'Token': ('ACA', 'AUSD', 'DOT', 'LDOT', 'RENBTC', 'CASH', 'KAR', 'KUSD', 'KSM', 'LKSM', 'TAI', 'BNC', 'VSKSM', 'PHA', 'KINT', 'KBTC'), 'Erc20': '[u8; 20]', 'LiquidCrowdloan': 'u32', 'ForeignAsset': 'u16'}), 
#   'Erc20': '[u8; 20]', 
#   'StableAssetPoolToken': 'u32', 
#   'LiquidCrowdloan': 'u32', 
#   'ForeignAsset': 'u16'
# }]
```

In the above examples are simple value `Enums` representation as a `tuple` of possible values and complex `Enums` as 
a `dict`.

## Examples (prior to MetadataV14)

### Decode a SCALE-encoded Compact\<Balance\> 

```python
RuntimeConfiguration().update_type_registry(load_type_registry_preset("legacy"))
RuntimeConfiguration().update_type_registry(load_type_registry_preset("kusama"))
obj = RuntimeConfiguration().create_scale_object('Compact<Balance>', data=ScaleBytes("0x130080cd103d71bc22"))
obj.decode()
print(obj.value)
```

### Encode to Compact\<Balance\> 

```python
RuntimeConfiguration().update_type_registry(load_type_registry_preset("legacy"))
obj = RuntimeConfiguration().create_scale_object('Compact<Balance>')
scale_data = obj.encode(2503000000000000000)
print(scale_data)
```

### Encode to Vec\<Bytes\>

```python
RuntimeConfiguration().update_type_registry(load_type_registry_preset("legacy"))
value = ['test', 'vec']
obj = RuntimeConfiguration().create_scale_object('Vec<Bytes>')
scale_data = obj.encode(value)
print(scale_data)
```

### Add custom types to type registry

```python
RuntimeConfiguration().update_type_registry(load_type_registry_preset("legacy"))

custom_types = {
    "types": {
        "MyCustomType": "u32",
        "CustomNextAuthority": {
          "type": "struct",
          "type_mapping": [
             ["AuthorityId", "AuthorityId"],
             ["weight", "AuthorityWeight"]
          ]
        }
    }   
}

RuntimeConfiguration().update_type_registry(custom_types)
```

### Or from a custom JSON file

```python
RuntimeConfiguration().update_type_registry(load_type_registry_preset("legacy"))
RuntimeConfiguration().update_type_registry(load_type_registry_file("/path/to/type_registry.json"))
```

### Multiple runtime configurations
By default a singleton is used to maintain the configuration, for multiple instances: 

```python
# Kusama runtime config
runtime_config_kusama = RuntimeConfigurationObject()
runtime_config_kusama.update_type_registry(load_type_registry_preset("legacy"))
runtime_config_kusama.update_type_registry(load_type_registry_preset("kusama"))


# Polkadot runtime config
runtime_config_polkadot = RuntimeConfigurationObject()
runtime_config_polkadot.update_type_registry(load_type_registry_preset("legacy"))
runtime_config_polkadot.update_type_registry(load_type_registry_preset("polkadot"))

# Decode extrinsic using Kusama runtime configuration
extrinsic = runtime_config_kusama.create_scale_object(
    type_string='Extrinsic', 
    metadata=metadata_decoder
)
extrinsic.decode(ScaleBytes(extrinsic_data))

```

## License
https://github.com/polkascan/py-scale-codec/blob/master/LICENSE
