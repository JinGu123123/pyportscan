"""端口范围解析模块"""


def parse_ports(s):
    """解析端口字符串，返回整数列表。

    支持格式：
        "80"              → [80]
        "22,80,443"       → [22, 80, 443]
        "8000-8005"       → [8000, 8001, ..., 8005]
        "22,8000-8002"    → [22, 8000, 8001, 8002]
    """
    ports = []
    for part in s.split(","):
        if "-" in part:
            start, end = part.split("-")
            ports.extend(range(int(start), int(end) + 1))
        else:
            ports.append(int(part))
    return ports
