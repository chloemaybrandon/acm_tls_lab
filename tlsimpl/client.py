"""
The actual TLS v1.3 client implementation.
"""

from __future__ import annotations

import hashlib
import socket
from typing import Any

from tlsimpl import cryptoimpl, handshake, util
from tlsimpl.consts import *


class TLSSocket:
    """
    A wrapper class around an inner socket.
    """

    inner: socket.socket
    client_params: cryptoimpl.AESParams | None = None
    server_params: cryptoimpl.AESParams | None = None
    transcript_hash: hashlib._Hash

    def __init__(self, inner: socket.socket) -> None:
        """
        Constructs a new TLSSocket instance from an inner socket.

        Performs the TLS handshake.
        """
        self.inner = inner
        self.send_seq_num = 0
        self.recv_seq_num = 0
        self.transcript_hash = hashlib.sha384()
        handshake.perform_handshake(self)

    @staticmethod
    def create_connection(*args: Any, **kwargs: Any) -> TLSSocket:
        """
        Utility function to create a TLS connection.
        """
        return TLSSocket(socket.create_connection(*args, **kwargs))

    def send_record(self, typ: RecordType, data: bytes) -> None:
        """
        Utility function to send a single record.

        Will encrypt the record if `self.encryption_key` is set.

        Records are specified in RFC8446 section 5.
        """
        data_len = len(data)
        if self.client_params is not None:
            # disguise as tls 1.2 packet
            data += util.pack(typ)
            data_len += 17  # 1 for the trailing byte, 16 for auth tag
            typ = RecordType.APPLICATION_DATA
        header = util.pack(typ) + b"\x03\x03" + util.pack(data_len, 2)
        if self.client_params is not None:
            data = self.client_params.encrypt(data, header)
        self.inner.sendall(header + data)

    def send_handshake_record(self, typ: HandshakeType, data: bytes) -> None:
        """
        Utility function to send a record containing a single handshake message.

        Records are specified in RFC8446 section 5.
        Handshake messages are specified in RFC8446 section 4.
        """
        packet = util.pack(typ) + util.pack(len(data), 3) + data
        self.transcript_hash.update(packet)
        self.send_record(RecordType.HANDSHAKE, packet)

    def recv_raw(self, length: int):
        """
        Utility function to receive a certain amount of bytes from the socket.

        Will only return fewer bytes if the client disconnects.
        """
        chunks = []
        while length > 0:
            temp = self.inner.recv(length)
            if not temp:
                break
            length -= len(temp)
            chunks.append(temp)
        return b"".join(chunks)

    def recv_record(self) -> tuple[RecordType, bytes]:
        """
        Utility function to receive a single record.

        Will decrypt the record if `self.encryption_key` is set.

        Records are specified in RFC8446 section 5.
        Nonce derivation is described in RFC8446 section 5.3.
        """
        header = self.recv_raw(5)
        ty = RecordType(header[0])
        count = util.unpack(header[3:5])
        data = self.recv_raw(count)
        if self.server_params is not None and ty == RecordType.APPLICATION_DATA:
            data = self.server_params.decrypt(data, header)
            # undisguise the tls 1.2 packet
            ty = RecordType(data[-1])
            data = data[:-1]
        return (ty, data)

    def recv_handshake_record(self) -> tuple[HandshakeType, bytes]:
        """
        Utility function to receive a record containing a single handshake message.

        Records are specified in RFC8446 section 5.
        Handshake messages are specified in RFC8446 section 4.
        """
        while True:
            (ty, data) = self.recv_record()
            # skip over all change_cipher_specs
            if ty != RecordType.CHANGE_CIPHER_SPEC:
                break
        assert ty == RecordType.HANDSHAKE
        self.transcript_hash.update(data)
        handshake_ty = HandshakeType(data[0])
        handshake_data = data[4:]
        assert util.unpack(data[1:4]) == len(handshake_data)
        return (handshake_ty, handshake_data)

    # The rest of these are just housekeeping functions
    def close(self) -> None:
        self.inner.close()

    def __enter__(self) -> None:
        self.inner.__enter__()

    def __exit__(self, *args: tuple[Any, ...]) -> None:
        self.inner.__exit__(*args)
