# Python SCALE Codec
[![Build Status](https://img.shields.io/github/workflow/status/polkascan/py-scale-codec/Run%20unit%20tests)](https://github.com/polkascan/py-scale-codec/actions?query=workflow%3A%22Run+unit+tests%22)
[![Latest Version](https://img.shields.io/pypi/v/scalecodec.svg)](https://pypi.org/project/scalecodec/) 
[![Supported Python versions](https://img.shields.io/pypi/pyversions/scalecodec.svg)](https://pypi.org/project/scalecodec/)
[![License](https://img.shields.io/pypi/l/scalecodec.svg)](https://github.com/polkascan/py-scale-codec/blob/master/LICENSE)

Python SCALE Codec Library

## Description
Most of the data that the Substrate RPCs output is encoded with the SCALE Codec. This codec is used by the Substrate nodes' internal runtime. In order to get to meaningful data this data will need to be decoded. The Python SCALE Codec Library will specialize in this task.

## Documentation
https://polkascan.github.io/py-scale-codec/

## Installation
```bash
pip install scalecodec
```

## Examples (MetadataV14 runtimes and higher)

Encode a Call

```python

runtime_config = RuntimeConfigurationObject()
# This types are all hardcoded types needed to decode metadata types
runtime_config.update_type_registry(load_type_registry_preset(name="metadata_types"))

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

Decode the result of a `state_getStorageAt` RPC call

```python
event_data = "0x2000000000000000b0338609000000000200000001000000000080b2e60e0000000002000000020000000003be1957935299d0be2f35b8856751feab95fc7089239366b52b72ca98249b94300000020000000500be1957935299d0be2f35b8856751feab95fc7089239366b52b72ca98249b943000264d2823000000000000000000000000000200000005027a9650a6bd43f1e0b4546affb88f8c14213e1fb60512692c2b39fbfcfc56b703be1957935299d0be2f35b8856751feab95fc7089239366b52b72ca98249b943000264d2823000000000000000000000000000200000013060c4c700700000000000000000000000000000200000005047b8441d5110c178c29be709793a41d73ae8b3119a971b18fbd20945ea5d622f00313dc01000000000000000000000000000002000000000010016b0b00000000000000"

system_pallet = [p for p in metadata.pallets if p['name'] == 'System'][0]
event_storage_function = [s for s in system_pallet['storage']['entries'] if s['name'] == "Events"][0]


event = runtime_config.create_scale_object(
    event_storage_function.get_value_type_string(), data=ScaleBytes(event_data), metadata=metadata
)
print(event.decode())
```

## Examples (prior to MetadataV14)

Decode a SCALE-encoded Compact\<Balance\> 

```python
RuntimeConfiguration().update_type_registry(load_type_registry_preset("default"))
RuntimeConfiguration().update_type_registry(load_type_registry_preset("kusama"))
obj = RuntimeConfiguration().create_scale_object('Compact<Balance>', data=ScaleBytes("0x130080cd103d71bc22"))
obj.decode()
print(obj.value)
```

Encode to Compact\<Balance\> 

```python
RuntimeConfiguration().update_type_registry(load_type_registry_preset("default"))
obj = RuntimeConfiguration().create_scale_object('Compact<Balance>')
scale_data = obj.encode(2503000000000000000)
print(scale_data)
```

Encode to Vec\<Bytes\>

```python
RuntimeConfiguration().update_type_registry(load_type_registry_preset("default"))
value = ['test', 'vec']
obj = RuntimeConfiguration().create_scale_object('Vec<Bytes>')
scale_data = obj.encode(value)
print(scale_data)
```

Add custom types to type registry

```python
RuntimeConfiguration().update_type_registry(load_type_registry_preset("default"))

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

Or from a custom JSON file

```python
RuntimeConfiguration().update_type_registry(load_type_registry_preset("default"))
RuntimeConfiguration().update_type_registry(load_type_registry_file("/path/to/type_registry.json"))
```

## Multiple runtime configurations
By default a singleton is used to maintain the configuration, for multiple instances: 

```python
# Kusama runtime config
runtime_config_kusama = RuntimeConfigurationObject()
runtime_config_kusama.update_type_registry(load_type_registry_preset("default"))
runtime_config_kusama.update_type_registry(load_type_registry_preset("kusama"))


# Polkadot runtime config
runtime_config_polkadot = RuntimeConfigurationObject()
runtime_config_polkadot.update_type_registry(load_type_registry_preset("default"))
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
