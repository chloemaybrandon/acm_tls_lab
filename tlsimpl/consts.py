"""
Various TLS-related constants.
"""

from enum import IntEnum


class HandshakeType(IntEnum):
    """
    A 1-byte identifier for a handshake packet.

    Specified in RFC8446 section 4.
    """

    CLIENT_HELLO = 1
    SERVER_HELLO = 2
    NEW_SESSION_TICKET = 4
    END_OF_EARLY_DATA = 5
    ENCRYPTED_EXTENSIONS = 8
    CERTIFICATE = 11
    CERTIFICATE_REQUEST = 13
    CERTIFICATE_VERIFY = 15
    FINISHED = 20
    KEY_UPDATE = 24
    MESSAGE_HASH = 254


class RecordType(IntEnum):
    """
    A 1-byte identifier for a record packet.

    Specified in RFC8446 section 5.1.
    """

    INVALID = 0
    CHANGE_CIPHER_SPEC = 20
    ALERT = 21
    HANDSHAKE = 22
    APPLICATION_DATA = 23


class CipherSuite(IntEnum):
    """
    A 2-byte identifier for a record packet.

    Specified in RFC8446 section 5.1.
    """

    TLS_AES_128_GCM_SHA256 = 0x1301
    TLS_AES_256_GCM_SHA384 = 0x1302
    TLS_CHACHA20_POLY1305_SHA256 = 0x1303
    TLS_AES_128_CCM_SHA256 = 0x1304
    TLS_AES_128_CCM_8_SHA256 = 0x1305


class ExtensionType(IntEnum):
    """
    A 2-byte identifier for a TLS extension.

    Specified in RFC8446 section 4.2.
    """

    SERVER_NAME = 0
    MAX_FRAGMENT_LENGTH = 1
    STATUS_REQUEST = 5
    SUPPORTED_GROUPS = 10
    SIGNATURE_ALGORITHMS = 13
    USE_SRTP = 14
    HEARTBEAT = 15
    APPLICATION_LAYER_PROTOCOL_NEGOTIATION = 16
    SIGNED_CERTIFICATE_TIMESTAMP = 18
    CLIENT_CERTIFICATE_TYPE = 19
    SERVER_CERTIFICATE_TYPE = 20
    PADDING = 21
    PRE_SHARED_KEY = 41
    EARLY_DATA = 42
    SUPPORTED_VERSIONS = 43
    COOKIE = 44
    PSK_KEY_EXCHANGE_MODES = 45
    CERTIFICATE_AUTHORITIES = 47
    OID_FILTERS = 48
    POST_HANDSHAKE_AUTH = 49
    SIGNATURE_ALGORITHMS_CERT = 50
    KEY_SHARE = 51


class SignatureScheme(IntEnum):
    """
    A 2-byte identifier for a signature scheme.

    Specified in RFC8446 section 4.2.3.
    """

    RSA_PKCS1_SHA256 = 0x0401
    RSA_PKCS1_SHA384 = 0x0501
    RSA_PKCS1_SHA512 = 0x0601
    ECDSA_SECP256R1_SHA256 = 0x0403
    ECDSA_SECP384R1_SHA384 = 0x0503
    ECDSA_SECP521R1_SHA512 = 0x0603
    RSA_PSS_RSAE_SHA256 = 0x0804
    RSA_PSS_RSAE_SHA384 = 0x0805
    RSA_PSS_RSAE_SHA512 = 0x0806
    ED25519 = 0x0807
    ED448 = 0x0808
    RSA_PSS_PSS_SHA256 = 0x0809
    RSA_PSS_PSS_SHA384 = 0x080A
    RSA_PSS_PSS_SHA512 = 0x080B
    RSA_PKCS1_SHA1 = 0x0201
    ECDSA_SHA1 = 0x0203


class NamedGroup(IntEnum):
    """
    A 2-byte identifier for a cryptographic group.

    Specified in RFC8446 section B.3.1.4.
    """

    SECP256R1 = 0x0017
    SECP384R1 = 0x0018
    SECP521R1 = 0x0019
    X25519 = 0x001D
    X448 = 0x001E
    FFDHE2048 = 0x0100
    FFDHE3072 = 0x0101
    FFDHE4096 = 0x0102
    FFDHE6144 = 0x0103
    FFDHE8192 = 0x0104
