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

"""多线程多端口"""
def scan_ports(host,ports,timeout = 1.0,max_workers = 200):
    open_ports = []

    """创建线程池
    with退出时自动关闭线程池"""
    with ThreadPoolExecutor(max_workers = max_workers) as executor:
        """futures等待结果
        (…):port for port in ports字典推导式,key:future;value:port
        """
        futures = {executor.submit(scan_port,host,port,timeout):port
                   for port in ports}
        for future in futures:
            port = futures[future]
            
            if future.result():
                open_ports.append(port)

    open_ports.sort()
    return open_ports


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
    result = scan_ports(args.host,ports,args.timeout,args.workers)
    print(f"开放端口{result}")


if __name__ == "__main__":
    main()