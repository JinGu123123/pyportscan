"""scan 模块的单元测试（用 mock 避免真实网络）"""

from unittest.mock import patch

from pyportscan.scan import scan_port


@patch("pyportscan.scan.socket.socket")
def test_scan_port_open(mock_socket_cls):
    """端口开放：connect_ex 返回 0 → scan_port 返回 True"""
    fake_sock = mock_socket_cls.return_value
    fake_sock.connect_ex.return_value = 0

    assert scan_port("127.0.0.1", 8000) is True


@patch("pyportscan.scan.socket.socket")
def test_scan_port_closed(mock_socket_cls):
    """端口关闭：connect_ex 返回非 0 → scan_port 返回 False"""
    fake_sock = mock_socket_cls.return_value
    fake_sock.connect_ex.return_value = 111    # ECONNREFUSED

    assert scan_port("127.0.0.1", 9999) is False


@patch("pyportscan.scan.socket.socket")
def test_scan_port_closes_socket(mock_socket_cls):
    """scan_port 必须关闭 socket"""
    fake_sock = mock_socket_cls.return_value
    fake_sock.connect_ex.return_value = 0

    scan_port("127.0.0.1", 8000)

    fake_sock.close.assert_called_once()       # 验证 close 被调用了一次
    fake_sock.close.assert_called_once()
    fake_sock.settimeout.assert_called_once()   # 新增：验证 settimeout 被调用
