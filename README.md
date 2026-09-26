# pyportscan

一个用 Python 实现的多线程 TCP 端口扫描器，用于学习网络安全和网络编程。

## 功能

- [x] 单端口 TCP Connect 扫描
- [x] 多端口范围扫描
- [x] 多线程并发加速
- [x] 命令行参数（argparse）
- [x] Banner Grabbing 服务识别
- [ ] 单元测试

## 环境

- Python 3.8+

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
