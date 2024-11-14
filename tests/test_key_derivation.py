from tlsimpl import cryptoimpl
from tlsimpl.cryptoimpl import *


def test_handshake_key_derivation():
    # same values as the one on https://tls13.xargs.org/#server-handshake-keys-calc
    transcript_hash = bytes.fromhex(
        "e05f64fcd082bdb0dce473adf669c2769f257a1c75a51b7887468b5e0e7a7de4f4d34555112077f16e079019d5a845bd"
    )
    shared_secret = bytes.fromhex(
        "df4a291baa1eb7cfa6934b29b474baad2697e29f1f920dcc77c8a0a088447624"
    )
    (handshake_secret, client_params, server_params) = (
        cryptoimpl.derive_handshake_params(shared_secret, transcript_hash)
    )
    assert (
        handshake_secret.hex()
        == "bdbbe8757494bef20de932598294ea65b5e6bf6dc5c02a960a2de2eaa9b07c929078d2caa0936231c38d1725f179d299"
    )
    assert (
        client_params.key.hex()
        == "1135b4826a9a70257e5a391ad93093dfd7c4214812f493b3e3daae1eb2b1ac69"
    )
    assert client_params.initial_nonce == 0x4256D2E0E88BABDD05EB2F27
    assert (
        server_params.key.hex()
        == "9f13575ce3f8cfc1df64a77ceaffe89700b492ad31b4fab01c4792be1b266b7f"
    )
    assert server_params.initial_nonce == 0x9563BC8B590F671F488D2DA3


def test_application_key_derivation():
    # same values as the one on https://tls13.xargs.org/#server-handshake-keys-calc
    transcript_hash = bytes.fromhex(
        "fa6800169a6baac19159524fa7b9721b41be3c9db6f3f93fa5ff7e3db3ece204d2b456c51046e40ec5312c55a86126f5"
    )
    handshake_secret = bytes.fromhex(
        "bdbbe8757494bef20de932598294ea65b5e6bf6dc5c02a960a2de2eaa9b07c929078d2caa0936231c38d1725f179d299"
    )
    (client_params, server_params) = cryptoimpl.derive_application_params(
        handshake_secret, transcript_hash
    )
    assert (
        client_params.key.hex()
        == "de2f4c7672723a692319873e5c227606691a32d1c59d8b9f51dbb9352e9ca9cc"
    )
    assert client_params.initial_nonce == 0xBB007956F474B25DE902432F
    assert (
        server_params.key.hex()
        == "01f78623f17e3edcc09e944027ba3218d57c8e0db93cd3ac419309274700ac27"
    )
    assert server_params.initial_nonce == 0x196A750B0C5049C0CC51A541
