"""pyportscan 命令行入口"""

import argparse

from pyportscan import parse_ports, scan_ports

import json
from datetime import datetime


def output_text(host, results, is_udp):
    """文本格式输出"""
    print(f"开放端口：")
    for port, info in results:
        if is_udp:
            print(f"  {port}/udp  {info}")
        else:
            if info:
                first_line = info.split("\n")[0]
                if len(first_line) > 80:
                    first_line = first_line[:77] + "..."
                print(f"  {port}/tcp  {first_line}")
            else:
                print(f"  {port}/tcp  (无法识别)")


def output_json(host, results, elapsed, is_udp):
    """JSON 格式输出"""
    data = {
        "host": host,
        "scan_time": datetime.now().isoformat(timespec="seconds"),
        "duration_seconds": round(elapsed, 3),
        "protocol": "udp" if is_udp else "tcp",
        "open_ports": [
            {"port": p, "banner": b} for p, b in results
        ],
    }
    print(json.dumps(data, ensure_ascii=False, indent=2))


def main():
    parser = argparse.ArgumentParser(
        description="一个多线程 TCP 端口扫描器"
    )
    parser.add_argument("host", help="目标主机（IP 或域名）")
    parser.add_argument("-p", "--ports", default="1-1024",
                        help="端口范围，如 80 或 22,80,443 或 1-1024（默认 1-1024）")
    parser.add_argument("-t", "--timeout", type=float, default=1.0,
                        help="连接超时秒数（默认 1.0）")
    parser.add_argument("-w", "--workers", type=int, default=100,
                        help="并发线程数（默认 100）")
    parser.add_argument("--no-banner", action="store_true",
                        help="不抓取服务 banner")
    parser.add_argument("--udp",action="store_true",
                        help="使用 UDP 扫描（默认TCP）")
    parser.add_argument("--json", action="store_true",
                        help="以 JSON 格式输出结果")

    args = parser.parse_args()

    ports = parse_ports(args.ports)

    import time
    if not args.json:
        print(f"开始扫描 {args.host}，端口数 {len(ports)}")

    start = time.time()
    results = scan_ports(
        args.host, ports, args.timeout, args.workers,
        grab=not args.no_banner,
        udp=args.udp,
    )
    elapsed = time.time() - start

    if args.json:
        output_json(args.host, results, elapsed, args.udp)
    else:
        output_text(args.host, results, args.udp)

if __name__ == "__main__":
    main()
