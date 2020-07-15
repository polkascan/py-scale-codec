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

## License
https://github.com/polkascan/py-scale-codec/blob/master/LICENSE
