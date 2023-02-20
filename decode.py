#!/usr/bin/env python
#
# Basic decoding of Olm messages within matrix to-device messages.
#
# Feed stdin with the json-encoded body of the to-device messages (one per line).
# Example for fishing them out of element-iOS-R logs:
#
#  zgrep QOYKSAYWSN console.log.gz | grep toDevice | sed -e 's/.* body: //' -e 's/)$//' | jq -r | jq '.["@travis:t2l.io"].QOYKSAYWSN.ciphertext["61IgqzLJu5zmubhtQHKG79xw+yqiMcx4uxkaAw+iShA"]' -cM | ~/work/decode_olm_messages/decode.py

import base64
import json
import sys
from typing import Callable, Dict, Optional, Sequence, Union

DecodedTagType = Union[int, Sequence[bytes]]
CustomDecoderType = Callable[[DecodedTagType], None]


class Reader:
    def __init__(self, data: Sequence[bytes], idx: int = 0, end: Optional[int] = None):
        self._data: Sequence[bytes] = data
        self._idx: int = idx
        self._end: int = end if end is not None else len(data)
        self._decoders: Dict[int, CustomDecoderType] = {}

    def register_decoder(self, tag: int, callback: CustomDecoderType) -> None:
        self._decoders[tag] = callback

    def read_byte(self) -> int:
        if self.is_empty():
            raise RuntimeError("hit end of data")

        res = int(self._data[self._idx])
        self._idx +=1
        return res

    def read_int(self) -> int:
        res = 0
        shift = 0
        while True:
            v = self.read_byte()
            res |= (v & 0x7F) << shift
            if not (v & 0x80):
                return res
            shift += 7

    def read_string(self) -> Sequence[bytes]:
        length = self.read_int()
        end = self._idx + length
        if end > self._end:
            raise RuntimeError("hit end of data")

        res = self._data[self._idx:end]
        self._idx = end
        return res

    def is_empty(self) -> bool:
        return self._idx >= self._end

    def dump(self) -> None:
        while not self.is_empty():
            tag = self.read_byte()
            typ = tag & 7
            if typ == 0:
                val = self.read_int()
                print("tag: %02x: val: %i" % (tag, val))
            elif typ == 2:
                val = self.read_string()
                if len(val) > 40:
                    x = bytes.hex(val[:40]) + "..."
                else:
                    x = bytes.hex(val)
                print("tag: %02x: val: %s" % (tag, x))
            else:
                raise RuntimeError(f"unknown tag type {typ}")
            dec = self._decoders.get(tag)
            if dec:
                print(">>>")
                dec(val)
                print("<<<")


def decode_msg(body: Sequence[bytes]) -> None:
    ver = int(body[0])
    print("Regular Olm message; ver: %02x" % (ver,))
    reader = Reader(body, 1, len(body) - 8)
    reader.dump()


def decode_prekey(body: Sequence[bytes]) -> None:
    ver = int(body[0])
    print("Prekey message: ver: %02x" % (ver,))
    reader = Reader(body, 1)
    reader.register_decoder(0x22, decode_msg)

    reader.dump()


def decode_unpadded_base64(input_string: str) -> bytes:
    """Decode an unpadded standard or urlsafe base64 string to bytes."""

    input_bytes = input_string.encode("ascii")
    input_len = len(input_bytes)
    padding = b"=" * (3 - ((input_len + 3) % 4))

    # Passing altchars here allows decoding both standard and urlsafe base64
    output_bytes = base64.b64decode(input_bytes + padding, altchars=b"-_")
    return output_bytes


if __name__ == "__main__":
    for line in sys.stdin:
        msg = json.loads(line)
        typ = msg['type']
        body = decode_unpadded_base64(msg['body'])

        if typ == 0:
            decode_prekey(body)
        elif typ == 1:
            decode_msg(body)
        else:
            raise RuntimeError("unknown Olm message type")

        print("---")
