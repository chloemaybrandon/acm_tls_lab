from tlsimpl import cryptoimpl


def test_nonce_increment():
    params = cryptoimpl.AESParams(b"", b"A" * 16, int.from_bytes(b"B" * 12, "big"))
    assert params.seq_num == 0
    assert params.get_nonce().hex() == "424242424242424242424242"
    assert params.seq_num == 1
    assert params.get_nonce().hex() == "424242424242424242424243"
    assert params.seq_num == 2
    assert params.get_nonce().hex() == "424242424242424242424240"
    assert params.seq_num == 3
    assert params.get_nonce().hex() == "424242424242424242424241"
    assert params.seq_num == 4
