"""
Utility functions for various aspects of TLS.
"""

from tlsimpl.consts import ExtensionType


def pack(num: int, width: int = 1) -> bytes:
    """
    Packs the integer `num` to `width` bytes.

    Specified in RFC8446 section 3.3.
    """
    return num.to_bytes(width, "big")


def unpack(data: bytes) -> int:
    """
    Unpacks the integer in `data`.

    Specified in RFC8446 section 3.3.
    """
    return int.from_bytes(data, "big")


def pack_varlen(data: bytes, len_width: int = 2) -> bytes:
    """
    Packs variable length data.
    `len_width` is the number of bytes to use for the length.

    Specified in RFC8446 section 3.4.
    """
    return len(data).to_bytes(len_width, "big") + data


def unpack_varlen(data: bytes, len_width: int = 2) -> tuple[bytes, bytes]:
    """
    Unpacks variable length data, returning a (data, remainder) tuple.
    `len_width` is the number of bytes to use for the length.

    Specified in RFC8446 section 3.4.
    """
    count = int.from_bytes(data[:len_width], "big")
    mid = len_width + count
    return (data[len_width:mid], data[mid:])


def pack_extension(ty: int, data: bytes) -> bytes:
    """
    Packs TLS extension data.

    Specified in RFC8446 section 4.2.
    """
    return pack(ty, 2) + pack_varlen(data)


def unpack_extension(data: bytes) -> tuple[ExtensionType, bytes, bytes]:
    """
    Unpacks TLS extension data.

    Returns an (extension type, extension data, remainder) tuple.

    Specified in RFC8446 section 4.2.
    """
    ty = int.from_bytes(data[:2], "big")
    return (ExtensionType(ty), *unpack_varlen(data[2:]))
