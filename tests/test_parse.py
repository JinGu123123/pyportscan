"""parse_ports 的单元测试"""

from pyportscan.parse import parse_ports


def test_single_port():
    assert parse_ports("80") == [80]


def test_multiple_ports():
    assert parse_ports("22,80,443") == [22, 80, 443]


def test_range():
    assert parse_ports("8000-8005") == [8000, 8001, 8002, 8003, 8004, 8005]


def test_mixed():
    assert parse_ports("22,8000-8002,3306") == [22, 8000, 8001, 8002, 3306]


def test_range_boundary():
    # range 的 +1 是经典坑，专门测边界
    assert parse_ports("1-1") == [1]
    assert parse_ports("65535-65535") == [65535]
