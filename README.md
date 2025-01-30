usage: 基于scapy进行扫描.py [-h] (--arp | --port | --tcp) --ip IP [--start-port START_PORT] [--end-port END_PORT]
                      [--dst-port DST_PORT]

Scapy 网络工具集

options:
  -h, --help            show this help message and exit
  --arp                 执行 ARP 扫描
  --port                执行端口扫描
  --tcp                 执行 TCP 三次握手及聊天
  --ip IP               目标 IP 地址或网段（例如 192.168.10.1 或 192.168.10.0/24）
  --start-port START_PORT
                        端口扫描起始端口（默认: 20）
  --end-port END_PORT   端口扫描结束端口（默认: 100）
