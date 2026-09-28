"""pyportscan 命令行入口"""

import argparse

from pyportscan import parse_ports, scan_ports


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

    args = parser.parse_args()

    ports = parse_ports(args.ports)

    print(f"开始扫描 {args.host}，端口数 {len(ports)}")
    results = scan_ports(
        args.host, ports, args.timeout, args.workers,
        grab=not args.no_banner,
    )

    print("开放端口：")
    for port, banner in results:
        if banner:
            first_line = banner.split("\n")[0]
            if len(first_line) > 80:
                first_line = first_line[:77] + "..."
            print(f"  {port}/tcp  {first_line}")
        else:
            print(f"  {port}/tcp  (无法识别)")


if __name__ == "__main__":
    main()
