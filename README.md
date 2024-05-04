# Python SCALE Codec

[![Build Status](https://img.shields.io/github/actions/workflow/status/polkascan/py-scale-codec/unittests.yml?branch=master)](https://github.com/polkascan/py-scale-codec/actions/workflows/unittests.yml?query=workflow%3A%22Run+unit+tests%22)
[![Latest Version](https://img.shields.io/pypi/v/scalecodec.svg)](https://pypi.org/project/scalecodec/) 
[![Supported Python versions](https://img.shields.io/pypi/pyversions/scalecodec.svg)](https://pypi.org/project/scalecodec/)
[![License](https://img.shields.io/pypi/l/scalecodec.svg)](https://github.com/polkascan/py-scale-codec/blob/master/LICENSE)


## Description
[Substrate](https://github.com/paritytech/substrate) uses a lightweight and efficient [encoding and decoding program](https://docs.substrate.io/reference/scale-codec/) to optimize how data is sent and received over the network. The program used to serialize and deserialize data is called the SCALE codec, with SCALE being an acronym for **S**imple **C**oncatenated **A**ggregate **L**ittle-**E**ndian.

## Documentation
https://polkascan.github.io/py-scale-codec/


## Installation
```bash
pip install scalecodec
```

## Code examples

```python
from scalecodec.types import ScaleBytes, Bool, String, U32, U8, U16, Struct, Vec, Compact, Tuple, Enum

# encode a Vec<u16>
obj = Vec(U16).new()
value = [1, 2]
data = obj.encode(value)

# Define and decode a Struct
scale_obj = Struct(test=U8, test2=Tuple(U8, U8)).new()
value = scale_obj.decode(ScaleBytes("0x020105"))

# Define and encode an Enum
scale_obj = Enum(
    Bool=Bool(), 
    Number=U32, 
    Complex=Struct(data=String(), version=Compact(U8)), 
    None_=None
).new()
value = {'Bool': True}

data = scale_obj.encode(value)
```

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

## License
https://github.com/polkascan/py-scale-codec/blob/master/LICENSE
