"""服务 Banner 抓取模块"""

import socket


def grab_banner(host, port, timeout=2.0):
    """连接端口，尝试获取服务 banner。返回字符串，失败返回 None。"""
    sock = None
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((host, port))

        # 尝试1：被动接收（SSH/FTP/SMTP 主动发）
        try:
            data = sock.recv(1024)
            if data:
                return data.decode(errors="ignore").strip()
        except socket.timeout:
            pass

        # 尝试2：主动发 HTTP/1.1 请求
        try:
            req = (b"HEAD / HTTP/1.1\r\nHost: " + host.encode()
                   + b"\r\nConnection: close\r\n\r\n")
            sock.send(req)
            data = sock.recv(1024)
            if data:
                return data.decode(errors="ignore").strip()
        except socket.timeout:
            pass

        return None
    except (socket.error, OSError):
        return None
    finally:
        if sock:
            sock.close()
