"""banner 模块的单元测试（用 mock 避免真实网络）"""

import socket
from unittest.mock import patch

from pyportscan.banner import grab_banner


@patch("pyportscan.banner.socket.socket")
def test_grab_banner_receives_banner(mock_socket_cls):
    """被动接收成功：SSH 主动发 banner"""
    fake_sock = mock_socket_cls.return_value
    fake_sock.recv.return_value = b"SSH-2.0-OpenSSH_8.0\r\n"

    assert grab_banner("127.0.0.1", 22) == "SSH-2.0-OpenSSH_8.0"


@patch("pyportscan.banner.socket.socket")
def test_grab_banner_http_after_timeout(mock_socket_cls):
    """被动超时 + 主动 HTTP 请求成功"""
    fake_sock = mock_socket_cls.return_value
    # 第一次 recv 抛 timeout，第二次 recv 返回 HTTP 响应
    fake_sock.recv.side_effect = [
        socket.timeout(),
        b"HTTP/1.1 200 OK\r\nServer: nginx\r\n\r\n",
    ]

    result = grab_banner("127.0.0.1", 80)
    assert result is not None
    assert "200 OK" in result


@patch("pyportscan.banner.socket.socket")
def test_grab_banner_returns_none_on_timeout(mock_socket_cls):
    """两次 recv 都超时 → 返回 None"""
    fake_sock = mock_socket_cls.return_value
    fake_sock.recv.side_effect = socket.timeout

    assert grab_banner("127.0.0.1", 9999) is None


@patch("pyportscan.banner.socket.socket")
def test_grab_banner_handles_binary(mock_socket_cls):
    """响应含非 UTF-8 字节：不崩溃"""
    fake_sock = mock_socket_cls.return_value
    fake_sock.recv.return_value = b"\xff\xfe\x00\x01binary"

    result = grab_banner("127.0.0.1", 445)
    # 不应该抛异常；decode(errors="ignore") 会丢掉坏字节
    assert isinstance(result, str)
