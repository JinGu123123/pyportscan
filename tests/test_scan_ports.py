"""scan_ports 的集成测试（mock socket，真跑线程池）"""

import socket
from unittest.mock import patch

from pyportscan.scan import scan_ports


@patch("pyportscan.scan.socket.socket")
def test_scan_ports_tcp_no_banner(mock_socket_cls):
    """TCP 模式，grab=False：所有端口都开放"""
    fake_sock = mock_socket_cls.return_value
    fake_sock.connect_ex.return_value = 0      # 所有端口开放

    result = scan_ports("127.0.0.1", [80, 443], grab=False)

    assert (80, None) in result
    assert (443, None) in result
    assert len(result) == 2


@patch("pyportscan.scan.socket.socket")
def test_scan_ports_tcp_with_banner(mock_socket_cls):
    """TCP 模式，grab=True：抓 banner"""
    fake_sock = mock_socket_cls.return_value
    fake_sock.connect_ex.return_value = 0
    fake_sock.recv.return_value = b"HTTP/1.1 200 OK\r\n"

    result = scan_ports("127.0.0.1", [80], grab=True)

    assert len(result) == 1
    port, banner = result[0]
    assert port == 80
    assert "HTTP" in banner


@patch("pyportscan.scan.socket.socket")
def test_scan_ports_tcp_all_closed(mock_socket_cls):
    """TCP 模式，所有端口关闭：返回空列表"""
    fake_sock = mock_socket_cls.return_value
    fake_sock.connect_ex.return_value = 111    # 非 0 = 关闭

    result = scan_ports("127.0.0.1", [80, 443], grab=False)

    assert result == []


@patch("pyportscan.scan.socket.socket")
def test_scan_ports_udp(mock_socket_cls):
    """UDP 模式"""
    fake_sock = mock_socket_cls.return_value
    fake_sock.recvfrom.side_effect = socket.timeout    # 所有端口超时

    result = scan_ports("127.0.0.1", [53], udp=True)

    # 超时 → open|filtered，全部保留
    assert (53, "open|filtered") in result


@patch("pyportscan.scan.socket.socket")
def test_scan_ports_udp_mixed(mock_socket_cls):
    """UDP 模式：混合状态（closed 被过滤）"""
    fake_sock = mock_socket_cls.return_value
    # recvfrom 按顺序返回：第一次超时，第二次 ConnectionResetError
    fake_sock.recvfrom.side_effect = [
        socket.timeout(),
        ConnectionResetError(),
    ]

    result = scan_ports("127.0.0.1", [53, 9999], udp=True)

    # 53 → open|filtered，9999 → closed（被过滤）
    assert (53, "open|filtered") in result
    assert all(port != 9999 for port, _ in result)
