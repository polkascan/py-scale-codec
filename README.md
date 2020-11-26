# Python SCALE Codec
[![Travis CI Build Status](https://api.travis-ci.org/polkascan/py-scale-codec.svg?branch=master)](https://travis-ci.org/polkascan/py-scale-codec)
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

## Examples

Decode a SCALE-encoded Compact\<Balance\> 

```python
RuntimeConfiguration().update_type_registry(load_type_registry_preset("default"))
RuntimeConfiguration().update_type_registry(load_type_registry_preset("kusama"))
obj = ScaleDecoder.get_decoder_class('Compact<Balance>', ScaleBytes("0x130080cd103d71bc22"))
obj.decode()
print(obj.value)
```

Encode to Compact\<Balance\> 

```python
RuntimeConfiguration().update_type_registry(load_type_registry_preset("default"))
obj = ScaleDecoder.get_decoder_class('Compact<Balance>')
scale_data = obj.encode(2503000000000000000)
print(scale_data)
```

Encode to Vec\<Bytes\>

```python
RuntimeConfiguration().update_type_registry(load_type_registry_preset("default"))
value = ['test', 'vec']
obj = ScaleDecoder.get_decoder_class('Vec<Bytes>')
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
extrinsic = ScaleDecoder.get_decoder_class(
    type_string='Extrinsic', 
    data=ScaleBytes(extrinsic_data),
    metadata=metadata_decoder, 
    runtime_config=runtime_config_kusama
)
extrinsic.decode()

``` 

## Using the type registry updater in your application

To ensure the type registries are in sync with the current runtime of the blockchain, you can use 
the updater function in your application:

```python
from scalecodec.updater import update_type_registries

# Update type registries with latest version from Github   
try:
    update_type_registries()
except Exception:
    pass
```


## License
https://github.com/polkascan/py-scale-codec/blob/master/LICENSE
