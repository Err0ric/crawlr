import pytest

from routers.phone import normalize_phone


@pytest.mark.parametrize(
    "raw, expected",
    [
        ("2535551234", "+12535551234"),
        ("(253) 555-1234", "+12535551234"),
        ("253.555.1234", "+12535551234"),
        ("1-253-555-1234", "+12535551234"),
        ("+1 253 555 1234", "+12535551234"),
        ("+44 20 7946 0958", "+442079460958"),
        ("447946095800", "+447946095800"),
    ],
)
def test_normalize_phone(raw, expected):
    assert normalize_phone(raw) == expected


def test_normalize_strips_non_digits():
    assert normalize_phone("abc 253 def 555 ghi 1234") == "+12535551234"
