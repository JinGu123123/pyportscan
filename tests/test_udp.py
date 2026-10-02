"""UDP 扫描的单元测试（用 mock 避免真实网络）"""

import socket
from unittest.mock import patch

from pyportscan.scan import udp_scan_port


@patch("pyportscan.scan.socket.socket")
def test_udp_open(mock_socket_cls):
    """收到 UDP 响应 → open"""
    fake_sock = mock_socket_cls.return_value
    fake_sock.recvfrom.return_value = (b"response", ("127.0.0.1", 53))

    assert udp_scan_port("127.0.0.1", 53) == "open"


@patch("pyportscan.scan.socket.socket")
def test_udp_closed_win(mock_socket_cls):
    """Windows 上收到 ICMP unreachable → ConnectionResetError → closed"""
    fake_sock = mock_socket_cls.return_value
    fake_sock.recvfrom.side_effect = ConnectionResetError()

    assert udp_scan_port("127.0.0.1", 9999) == "closed"


@patch("pyportscan.scan.socket.socket")
def test_udp_closed_linux(mock_socket_cls):
    """Linux 上收到 ICMP unreachable → ConnectionRefusedError → closed"""
    fake_sock = mock_socket_cls.return_value
    fake_sock.recvfrom.side_effect = ConnectionRefusedError()

    assert udp_scan_port("127.0.0.1", 9999) == "closed"


@patch("pyportscan.scan.socket.socket")
def test_udp_filtered(mock_socket_cls):
    """超时 → open|filtered"""
    fake_sock = mock_socket_cls.return_value
    fake_sock.recvfrom.side_effect = socket.timeout()

    assert udp_scan_port("8.8.8.8", 53) == "open|filtered"
