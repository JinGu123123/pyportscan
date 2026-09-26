import socket
from concurrent.futures import ThreadPoolExecutor
import argparse


def parse_ports(s):
    ports = []
    for part in s.split(","):
        if "-" in part:
            start,end =part.split("-")
            ports.extend(range(int(start),int(end) + 1))
        else:
            ports.append(int(part))
    return ports


"""单线程单端口"""
def scan_port(host,port,timeout = 1.0):
    sock = socket.socket(socket.AF_INET,socket.SOCK_STREAM)

#settimeout保证若超时connect_ex会跳过，继续下一个
    sock.settimeout(timeout)
    try:
        #connect_ex失败会返回一个错误码（成功返回0，失败返回其他），接受一个参数，传入元组
        result = sock.connect_ex((host,port))
        return result == 0
    finally:
        sock.close()


def grab_banner(host,port,timeout = 2.0):
    sock = None
    try:
        sock = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
        sock.settimeout(1.0)
        sock.connect((host,port))

        try:
            data = sock.recv(1024)

            if data:
                return data.decode(errors="ignore").strip()

        except socket.timeout:
            pass

        try:
            """Python 3.14的http.server更严格,拒绝HTTP/1.0请求
            请求头加Host,版本协议为1,1
            """
            req = b"HEAD / HTTP/1.1\r\nHost:" + host.encode() + b"\r\nConnection:close\r\n\r\n"
            sock.send(req)
            data = sock.recv(1024)
            if data:
                return data.decode(errors="ignore")

        except socket.timeout:
            pass

        return None

    except (socket.error,OSError):
        return None

    finally:
        if sock:
            sock.close()


"""多线程多端口"""
def scan_ports(host,ports,timeout = 1.0,max_workers = 200,grab = False):
    open_ports = []

    """创建线程池
    with退出时自动关闭线程池"""
    with ThreadPoolExecutor(max_workers = max_workers) as executor:
        """futures等待结果
        (…):port for port in ports字典推导式,key:future;value:port
        """
        futures = {executor.submit(scan_port,host,port,timeout):port
                   for port in ports}
        for future,port in futures.items():
            
            if future.result():
                open_ports.append(port)

    if not grab:
        return sorted([(p,None) for p in open_ports])
    
    results = []
    with ThreadPoolExecutor(max_workers = max_workers) as executor:
        futures = {executor.submit(grab_banner,host,port,timeout):port
                   for port in open_ports}
        for future,port in futures.items():
            banner = future.result()
            results.append((port,banner))

    results.sort()
    return results


def main():
    parser = argparse.ArgumentParser(
        description = "一个多线程TCP端口扫描器"
    )

    parser.add_argument("host",help = "目标主机(IP或域名)")
    parser.add_argument("-p","--ports",default = "1-1024",
                        help = "端口范围,如80或22,80,443,或1-1024")
    parser.add_argument("-t","--timeout",type = float,default = "1.0",
                        help = "连接超时秒数(默认1.0)")
    parser.add_argument("-w","--workers",type = int,default = "100",
                        help = "并发线程数(默认100)")


    args = parser.parse_args()

    ports = parse_ports(args.ports)


    print(f"开始扫描{args.host},端口数{len(ports)}")
    results = scan_ports(args.host,ports,args.timeout,args.workers,grab = True)
    print(f"开放端口:")
    for port,banner in results:
        if banner:
            first_line = banner.split("\n")[0]
            print(f"{port}/tcp {first_line}")

        else:
            print(f"{port}/tcp (无法识别)")


if __name__ == "__main__":
    main()