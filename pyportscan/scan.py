"""TCP 端口扫描模块"""

import socket
from concurrent.futures import ThreadPoolExecutor


def scan_port(host, port, timeout=1.0):
    """扫描单个 TCP 端口。返回 True 表示开放。"""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        result = sock.connect_ex((host, port))
        return result == 0
    finally:
        sock.close()


def udp_scan_port(host,port,timeout = 2.0):
    sock = socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    try:
        sock.sendto(b"",(host,port))
        try:
            data, _ = sock.recvfrom(1024)
            return "open"
        except socket.timeout:
            return "open|filtered"
        except (ConnectionRefusedError,ConnectionResetError):
            return "closed"
    finally:
        sock.close()


def scan_ports(host, ports, timeout=1.0, max_workers=200, grab=False,udp=False,on_progress=None):
    """
    on_prograss:可选回调，每扫完一个端口调用一次
                签名：on_progress(done,total,open_ports)
    """

    """并发扫描多个端口。

    参数:
        host: 目标主机
        ports: 端口列表
        timeout: 单个端口超时
        max_workers: 并发线程数
        grab: 是否抓取 banner

    返回:
        TCP (udp=False):
            grab=False → [(port, None), ...]（仅开放端口）
            grab=True  → [(port, banner), ...]
        UDP (udp=True):
            [(port, state), ...]   # state ∈ {"open", "closed", "open|filtered"}
    """

    ports = list(ports)
    total = len(ports)
    done = 0

    # 第一步：并发扫描端口
    open_ports = []
    #UDP
    if udp:
        results = []
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = {executor.submit(udp_scan_port,host,port,timeout):port
                       for port in ports}
            for future, port in futures.items():
                done += 1
                if on_progress:
                    on_progress(done,total,results)
                state = future.result()
                if state != "closed":
                    results.append((port,state))
        results.sort()
        return results        

            
    #TCP
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(scan_port, host, port, timeout): port
                    for port in ports}
        for future, port in futures.items():
            done += 1
            if on_progress:
                on_progress(done,total,open_ports)
            if future.result():
                open_ports.append(port)

    # 第二步：不抓 banner 直接返回
    if not grab:
        return sorted([(p, None) for p in open_ports])

    # 第三步：并发抓 banner
    from .banner import grab_banner    # 延迟导入，避免循环依赖
    results = []
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(grab_banner, host, port, timeout): port
                   for port in open_ports}
        for future, port in futures.items():
            banner = future.result()
            results.append((port, banner))

    results.sort()
    return results
