"""
The TLS v1.3 handshake implementation.
"""

from __future__ import annotations

import secrets

import os
from tlsimpl import client, cryptoimpl, util
from tlsimpl.consts import *


def send_client_hello(sock, key_exchange_pubkey: bytes) -> None:
    """
    Performs the TLS v1.3 client hello.

    `key_exchange_pubkey` is the Ed25519 public key used for key exchange.

    Specified in RFC8446 section 4.1.2.
    """

    # # Client Random
    client_random = os.urandom(32)

    cipher_suites = b"\x00\x02\x13\x02"

    compression_methods = b"\x01\x00"

    # Extensions:
    supported_versions = b"\x00\x2b\x00\x03\x02\x03\x04"
    signature_algorithms = b"\x00\x0d\x00\x04\x00\x02\x08\x04"
    
    key_exchange_pubkey_internal = util.pack_varlen(b"".join ([b"\x00\x1d\x00\x20", key_exchange_pubkey]))
    key_exchange_pubkey_external = util.pack_varlen(key_exchange_pubkey_internal)

    key_share = b"\x00\x33" + key_exchange_pubkey_external
    supported_groups = b"\x00\x0a\x00\x04\x00\x02\x00\x1d"

    extensions = b"".join([supported_versions, signature_algorithms, key_share, supported_groups])
    extension_length = (len(extensions)).to_bytes(2, 'big')

    packet = [b"\x03\x03", client_random, b"\x00", cipher_suites, compression_methods, extension_length, extensions]

    # TODO: construct the packet data
    sock.send_handshake_record(HandshakeType.CLIENT_HELLO, b"".join(packet))


def recv_server_hello(sock: client.TLSSocket) -> bytes:
    """
    Parses the TLS v1.3 server hello.

    Returns the pubkey of the server.

    Specified in RFC8446 section 4.1.3.
    """

    (ty, data) = sock.recv_handshake_record()

    print(f"\n** recv_server_hello received record type: {ty}")
    if ty == RecordType.ALERT:
        alert_level = data[0]
        alert_description = data[1]
        print(f"Alert Level: {alert_level}, Alert Description: {alert_description}\n")

    assert ty == HandshakeType.SERVER_HELLO
    # TODO: parse server hello and find server pubkey

    # print("Data Here******************\n")
    # print(ty)
    # #print(util.unpack(data))
    # print("\n")

    # After the ty, there are 3 more bytes of length data
    parse_server_version = data[0:2]
    parse_client_random = data[2:34]

    # First byte of session ID will be the len of the session ID
    # In this case, it is hard coded \x00, but this will parse properly regardless
    parse_session_id_len = data[34:35]
    sid_end = 35 + util.unpack(parse_session_id_len)
    parse_session_id_data = data[35:sid_end]
    parse_entire_session_id = parse_session_id_len + parse_session_id_data

    csuite_end = 2 + sid_end
    parse_cipher_suite = data[sid_end:csuite_end]

    comp_end = csuite_end + 1
    parse_compression_method = data[csuite_end:comp_end]
    
    extlen_end = comp_end + 2
    exten_len = util.unpack(data[comp_end:extlen_end])
    exten_end = extlen_end + exten_len
    parse_extensions = data[extlen_end:exten_end]

    # Look for pubkey extension '00 33' indicator in parse_extensions
    # for i in range (0, exten_len):

    # Validate the cipher suite
    # Public key from extension parsing


    if (parse_extensions[0:2]).hex() == "002b":
        # print("002b found")
        begin_key_index = extlen_end + 12
    elif (parse_extensions[0:2]).hex() == b"0033":
        # print("0033 found")
        begin_key_index = extlen_end + 6
    else:
        print("Error: no pubkey exten found\n")

    end_key_index = begin_key_index + 32

    # This is what we are actually returning
    parse_pubkey = data[begin_key_index:end_key_index]

    # Print spaced pubkey
    hex_pubkey = parse_pubkey.hex()
    spaced_pubkey = ' '.join(hex_pubkey[i:i+2] for i in range(0, len(hex_pubkey), 2))

    print("Test Print Here******************")
    print(spaced_pubkey)
    print(len(hex_pubkey)/2)
    print("*********************************")
    print("\n")

    
    # peer_pubkey = b"???"
    peer_pubkey = parse_pubkey
    return peer_pubkey


# def send_client_hello(sock, key_exchange_pubkey: bytes) -> None:
#     """
#     Performs the TLS v1.3 client hello.

#     `key_exchange_pubkey` is the X25519 public key used for key exchange.

#     Specified in RFC8446 section 4.1.2.
#     """
#     packet = []
#     # TODO: construct the packet data
#     sock.send_handshake_record(HandshakeType.CLIENT_HELLO, b"".join(packet))


# def recv_server_hello(sock: client.TLSSocket) -> bytes:
#     """
#     Parses the TLS v1.3 server hello.

#     Returns the pubkey of the server.

#     Specified in RFC8446 section 4.1.3.
#     """
#     (ty, data) = sock.recv_handshake_record()
#     assert ty == HandshakeType.SERVER_HELLO
#     # TODO: parse server hello and find server pubkey
#     peer_pubkey = b"???"
#     return peer_pubkey




def recv_server_info(sock: client.TLSSocket) -> None:
    """
    Receives the server's encrypted extensions, certificate, and certificate verification.

    Also verifies the certificate's validity.
    """
    # TODO: implement


def finish_handshake(sock: client.TLSSocket, handshake_secret: bytes) -> None:
    """
    Receives the server finish, sends the client finish, and derives the application keys.

    Takes in the shared secret from key exchange.
    """
    # TODO: implement


def perform_handshake(sock: client.TLSSocket) -> None:
    key_exchange_keypair = cryptoimpl.generate_x25519_keypair()
    send_client_hello(sock, key_exchange_keypair[1])

    peer_pubkey = recv_server_hello(sock)

    shared_secret = cryptoimpl.derive_shared_x25519_key(
        key_exchange_keypair[0], peer_pubkey
    )

    transcript_hash = sock.transcript_hash.digest()
    
    (handshake_secret, sock.client_params, sock.server_params) = (
        cryptoimpl.derive_handshake_params(shared_secret, transcript_hash)
    )

    recv_server_info(sock)
    finish_handshake(sock, handshake_secret)
    # receive an encrypted record to make sure everything works
    print(sock.recv_record())
