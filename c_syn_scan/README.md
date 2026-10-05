# C 语言 SYN 半开扫描

包含两个版本，用于对比"核心逻辑"和"环境适配"。

## 文件说明

| 文件 | 说明 |
|:---|:---|
| **`syn_scan_core.c`** | **80 行核心版**——只依赖原始套接字，在**真实 Linux** 上可工作 |
| **`syn_scan_wsl2.c`** | **200 行 WSL2 适配版**——用 libpcap + pcap_sendpacket 尝试绕过 WSL2 网络隔离 |

## 编译

```bash
# 核心版（无外部依赖）
gcc -o syn_scan_core syn_scan_core.c

# WSL2 版（需要 libpcap）
gcc -o syn_scan_wsl2 syn_scan_wsl2.c -lpcap
