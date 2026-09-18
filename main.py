import socket
from concurrent.futures import ThreadPoolExecutor


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
        futures = {excutor.submit(scan_port,host,port,timeout):port
                   for port in ports}
        for future in futures:
            port = futures[future]
            print(future.done())
            if future.result():
                print(future.done())
                open_ports.append(port)

    open_ports.sort()
    return open_ports

if __name__ == "__main__":
    import time
    start = time.time()
    result = scan_ports('192.168.31.21',range(1,1025),timeout = 1.0,max_workers = 200)
    elpased = time.time() - start
    print(f"开放端口：{result}")
    print(f"扫描时间：{elpased:.2f}秒")
