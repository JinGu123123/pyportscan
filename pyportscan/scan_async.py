"""基于asyncio的异步端口扫描"""

import asyncio


async def scan_port_async(host,port,timeout=1.0,semaphore=None):
    """异步扫描单个TCP端口
    参数：
        semaphore:可选的 asyncio.Semaphore,用于限流
    返回：
        True表示端口开放,False表示端口关闭/超时
    """

    if semaphore is not None:
        async with semaphore:
            return await _try_connect(host,port,timeout)
    return await _try_connect(host,port,timeout)



async def _try_connect(host,port,timeout):
    #内部：尝试连接

    try:
        reader,writer = await asyncio.wait_for(
            asyncio.open_connection(host,port),
            timeout=timeout,
        )
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass
        return True
    except(asyncio.TimeoutError,ConnectionRefusedError,OSError):
        return False



async def scan_ports_async(host,ports,timeout=1.0,max_concurrent=500):
    """异步并发扫描多个端口
    参数：
        host:目标主机
        ports:端口列表(或range)
        timeout:单个端口超时
        max_concurrent:最大并发数

    返回：
        [(port,None),...](暂不抓banner,格式与scan_ports一致)
    """

    ports = list(ports)
    semaphore = asyncio.Semaphore(max_concurrent)

    tasks = [
        scan_port_async(host,port,timeout,semaphore)
        for port in ports
    ]
    results = await asyncio.gather(*tasks)

    open_ports = [p for p, ok in zip(ports,results)if ok]
    open_ports.sort()
    return [(p,None) for p in open_ports]