"""pyportscan 命令行入口"""

import argparse
import time

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


def build_json(host, results, elapsed, is_udp):
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
    return json.dumps(data, ensure_ascii=False, indent=2)


def make_progress_callback():
    #构造一个进度回调（节流：每100个端口或每5%打印一次）
    last_printed = [0]

    def callback(done,total,open_ports):
        step = max(100,total // 20)
        if done - last_printed[0] < step and done != total:
            return

        last_printed[0] = done
        pct = done * 100 / total
        print(f"[.]进度:{done}/{total}({pct:.1f}%) - 已发现{len(open_ports)}个开放端口")

    return callback


def main():
    parser = argparse.ArgumentParser(
        description="一个多线程 TCP 端口扫描器"
    )
    parser.add_argument("host", help="目标主机(IP 或域名)")
    parser.add_argument("-t", "--timeout", type=float, default=1.0,
                        help="连接超时秒数(默认 1.0)")
    parser.add_argument("-w", "--workers", type=int, default=100,
                        help="并发线程数(默认 100)")
    parser.add_argument("--no-banner", action="store_true",
                        help="不抓取服务 banner")
    parser.add_argument("--udp",action="store_true",
                        help="使用 UDP 扫描(默认TCP)")
    parser.add_argument("--json", action="store_true",
                        help="以 JSON 格式输出结果")
    parser.add_argument("--output", "-o", metavar="FILE",
                        help="将结果写入文件(需配合 --json)")
    parser.add_argument("-v","--verbose",action="store_true",
                        help="显示详细进度")
    parser.add_argument("--exclude-ports",metavar="PORTS",
                        help="排除指定端口,如135,445或1000-2000")
    parser.add_argument("--async-mode",action="store_true",dest="use_async",
                        help="使用asyncio异步扫描(默认多线程)")

    group = parser.add_mutually_exclusive_group()
    group.add_argument("-p", "--ports", default=None,
                        help="端口范围，如 80 或 22,80,443 或 1-1024")
    group.add_argument("--top-ports",type=int,metavar="N",
                        help="扫描最常用的N个端口(100)")


    args = parser.parse_args()


    from pyportscan.ports import TOP_PORTS

    if args.top_ports:
        n = min(args.top_ports,len(TOP_PORTS))
        ports = TOP_PORTS[:n]
    elif args.ports:
        ports = parse_ports(args.ports)
    else:
        ports = list(range(1,1025))


    if args.use_async:
        if args.udp:
            parser.error("--async-mode暂不支持--udp")
        if not args.no_banner:
            print("[!]注意：--async-mode暂不抓取banner")



    if args.exclude_ports:
        exclude = set(parse_ports(args.exclude_ports))
        ports = [p for p in ports if p not in exclude]


    if args.output and not args.json:
        parser.error("--output 需要配合 --json 使用")



    if not args.json and args.verbose:
        print(f"[*]开始扫描 {args.host}")
        print(f"[*]端口数:{len(ports)}个")
    if args.use_async:
        print(f"[*]模式：asyncio异步(并发{args.workers * 5})")
    else:
        print(f"[*]模式：多线程(并发{args.workers})")
    print(f"[*]超时：{args.timeout}秒")


    #=====扫描入口=====
    start = time.time()

    if args.use_async:
        import asyncio
        from pyportscan.scan_async import scan_ports_async

        results = asyncio.run(scan_ports_async(
            args.host,ports,
            timeout=args.timeout,
            max_concurrent=args.workers * 5,
        ))
    else:
        on_progress = make_progress_callback() if (args.verbose and not args.json) else None
        results = scan_ports(
            args.host,ports,args.timeout,args.workers,
            grab=args.no_banner,
            udp=args.udp,
            on_progress=on_progress,
        )

    elapsed = time.time() - start


    #=====输出结果=====
    if args.json:
        json_str = build_json(args.host, results, elapsed, args.udp)
        if args.output:
            with open(args.output, "w", encoding="utf-8") as f:
                f.write(json_str)
            print(f"[+] 结果已写入 {args.output}")
        else:
            print(json_str)
    else:
        if args.verbose and not args.json:
            print(f"[+]扫描完成:{len(results)}个开放端口,耗时{elapsed:.2f}秒")
        output_text(args.host, results, args.udp)

if __name__ == "__main__":
    main()
