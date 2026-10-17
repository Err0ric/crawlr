import pytest

from routers.hash_lookup import detect_hash_type


@pytest.mark.parametrize(
    "value, expected",
    [
        ("d41d8cd98f00b204e9800998ecf8427e", "MD5"),
        ("DA39A3EE5E6B4B0D3255BFEF95601890AFD80709", "SHA1"),
        ("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "SHA256"),
        ("  d41d8cd98f00b204e9800998ecf8427e  ", "MD5"),
    ],
)
def test_detect_hash_type_valid(value, expected):
    assert detect_hash_type(value) == expected


@pytest.mark.parametrize(
    "value",
    [
        "",
        "not-a-hash",
        "d41d8cd98f00b204e9800998ecf8427",          # 31 chars
        "d41d8cd98f00b204e9800998ecf8427ez",         # non-hex char
        "0123456789abcdef0123456789abcdef0123456789abcdef",  # 48 chars
    ],
)
def test_detect_hash_type_invalid(value):
    assert detect_hash_type(value) is None
