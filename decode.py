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
from typing import Callable, Dict, Iterable, Iterator, Optional, Union, cast

DecodedTagType = Union[int, bytes]
CustomDecoderType = Callable[[DecodedTagType], None]


class Reader:
    def __init__(self, data: bytes, idx: int = 0, end: Optional[int] = None):
        if end is None:
            end = len(data)
        self._data: Iterator[int] = iter(data[idx:end])
        self._decoders: Dict[int, CustomDecoderType] = {}

    def register_decoder(self, tag: int, callback: CustomDecoderType) -> None:
        self._decoders[tag] = callback

    def read_byte(self) -> int:
        """Get the next byte from the message

        Raises StopIteration if we've hit the end of the input
        """
        return next(self._data)

    def read_int(self) -> int:
        """Read a variable-length-encoded int from the message

        Raises StopIteration if we hit the end of the input
        """
        res = 0
        shift = 0
        while True:
            v = self.read_byte()
            res |= (v & 0x7F) << shift
            if not (v & 0x80):
                return res
            shift += 7

    def read_string(self) -> bytes:
        """Read a string from the message

        Raises StopIteration if we hit the end of the input
        """
        length = self.read_int()

        def readn(n: int) -> Iterable[int]:
            while n > 0:
                yield self.read_byte()
                n -= 1

        return bytearray(readn(length))

    def dump(self) -> None:
        """Dump the whole of the message"""
        while True:
            try:
                tag = self.read_byte()
            except StopIteration:
                return

            typ = tag & 7
            val: DecodedTagType
            if typ == 0:
                val = self.read_int()
                print("tag: %02x: val: %i" % (tag, val))
            elif typ == 2:
                val = self.read_string()
                if len(val) > 40:
                    x = val[:40].hex() + "..."
                else:
                    x = val.hex()
                print("tag: %02x: val: %s" % (tag, x))
            else:
                raise RuntimeError(f"unknown tag type {typ}")
            dec = self._decoders.get(tag)
            if dec:
                print(">>>")
                dec(val)
                print("<<<")


def decode_msg(body: bytes) -> None:
    ver = int(body[0])
    print("Regular Olm message; ver: %02x" % (ver,))
    # exclude the MAC
    reader = Reader(body, 1, len(body) - 8)
    reader.dump()
    print("MAC:", body[-8:].hex())


def decode_prekey(body: bytes) -> None:
    ver = int(body[0])
    print("Prekey message: ver: %02x" % (ver,))
    reader = Reader(body, 1)

    def on_msg(msg: Union[int, bytes]) -> None:
        decode_msg(cast(bytes, msg))

    reader.register_decoder(0x22, on_msg)

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
        typ = msg["type"]
        body = decode_unpadded_base64(msg["body"])

        if typ == 0:
            decode_prekey(body)
        elif typ == 1:
            decode_msg(body)
        else:
            raise RuntimeError("unknown Olm message type")

        print("---")
