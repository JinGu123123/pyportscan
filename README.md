# pyportscan

一个用 Python 实现的多线程 TCP 端口扫描器，支持端口范围解析、并发扫描和 Banner 抓取。用于学习网络安全与网络编程。

## 功能

- [x] 单端口 / 多端口 / 端口范围扫描
- [x] 多线程并发加速
- [x] 灵活的命令行参数（argparse）
- [x] Banner Grabbing 服务识别
- [x] 模块化设计，可作为 Python 库使用
- [x] 单元测试覆盖核心逻辑
- [x] UDP 扫描（计划中）
- [ ] 导出扫描结果到 JSON/CSV（计划中）

## 环境要求

- Python 3.8+
- 依赖见 `requirements.txt`

## 开发环境

### Python 部分
- Python 3.8+
- pytest（测试）

### C 语言 SYN 扫描（阶段 7.3 准备）
- WSL2（Windows Subsystem for Linux 2）
- Ubuntu 26.04 LTS
- gcc 15.2.0
- make 4.4.1
- libpcap-dev

#### 在 WSL2 里安装

```bash
sudo apt update
sudo apt install -y gcc make libpcap-dev

## 安装

```bash
git clone git@github.com:JinGu123123/pyportscan.git
cd pyportscan
pip install -r requirements.txt
```

## 使用

### 基本用法

```bash
# 扫描本机默认端口（1-1024）
python main.py 127.0.0.1

# 扫描指定端口
python main.py 127.0.0.1 -p 22,80,443,8000

# 扫描端口范围
python main.py 127.0.0.1 -p 1-1024

# 混合格式
python main.py 127.0.0.1 -p 22,80,8000-8100,3306

# 不抓取 banner（更快）
python main.py 127.0.0.1 -p 1-1024 --no-banner

# UDP 扫描
python main.py 127.0.0.1 -p 53,123,161 --udp

# 查看帮助
python main.py -h
```

### 参数说明

| 参数 | 说明 | 默认值 |
|------|------|--------|
| `host` | 目标主机（IP 或域名，必填） | - |
| `-p, --ports` | 端口范围 | `1-1024` |
| `-t, --timeout` | 连接超时（秒） | `1.0` |
| `-w, --workers` | 并发线程数 | `100` |
| `--no-banner` | 不抓取服务 banner | 关闭 |
| `--udp` | 使用 UDP 扫描（默认 TCP） | 关闭 |
| `-h, --help` | 显示帮助 | - |

### 示例输出

```
$ python main.py 127.0.0.1 -p 1-1024
开始扫描 127.0.0.1，端口数 1024
开放端口：
  135/tcp  (无法识别)
  445/tcp  (无法识别)
  902/tcp  220 VMware Authentication Daemon Version 1.10: SSL Required...
  912/tcp  220 VMware Authentication Daemon Version 1.0, ServerDaemonProtocol:SOAP...
```

## Python API 用法

除了命令行，`pyportscan` 也可以作为 Python 库使用：

```python
from pyportscan import parse_ports, scan_ports, grab_banner

# 解析端口字符串
ports = parse_ports("22,80,8000-8100")      # [22, 80, 8000, ..., 8100]

# 扫描端口（不抓 banner）
results = scan_ports("127.0.0.1", ports, grab=False)

# 扫描端口并抓取 banner
results = scan_ports("127.0.0.1", [8000], grab=True)
for port, banner in results:
    print(port, banner)

# 单独抓取某个端口的 banner
banner = grab_banner("127.0.0.1", 8000)

# UDP 扫描
results = scan_ports("127.0.0.1", [53, 123], udp=True)
# [(53, 'open|filtered'), ...]
```

## 项目结构

```
pyportscan/
├── pyportscan/              # 核心包
│   ├── __init__.py          # 统一暴露 API
│   ├── parse.py             # 端口范围解析
│   ├── scan.py              # 端口扫描
│   └── banner.py            # banner 抓取
├── tests/                   # 单元测试
│   ├── test_parse.py
│   ├── test_scan.py
│   └── test_banner.py
├── main.py                  # CLI 入口
├── requirements.txt
├── README.md
└── LICENSE
```

## 运行测试

```bash
# 安装测试依赖
pip install -r requirements.txt

# 运行全部测试
pytest tests/ -v

# 只运行某个测试文件
pytest tests/test_parse.py -v
```

## 开发进度

- [x] 阶段 0-3：基础扫描 + 并发扫描
- [x] 阶段 4：命令行工具（argparse）
- [x] 阶段 5：Banner Grabbing 服务识别
- [x] 阶段 6：单元测试 + 项目整理
- [x] 阶段 7.1：UDP 扫描
- [x] 阶段 7.2：搭建 WSL2 开发环境
- [ ] 阶段 7.3：C 语言 SYN 半开扫描
## 免责声明

本工具仅供学习与授权测试使用。请勿用于未授权的目标，否则后果自负。

## License

[MIT](LICENSE)
