import logging
import random
import argparse

from scapy.arch import get_if_hwaddr
from scapy.config import conf
from scapy.layers.inet import TCP, IP
from scapy.layers.l2 import ARP
from scapy.packet import Raw
from scapy.sendrecv import sr1, send

# 配置Scapy日志级别
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)


def scapy_ip(start, end=10, network='192.168.10.'):
    local_mac = get_if_hwaddr(conf.iface)
    for i in range(start, start + end):
        ip = f'{network}{i}'
        try:
            pkg = ARP(op=1, psrc=ip, hwsrc=local_mac, pdst=ip)
            reply = sr1(pkg, timeout=3, verbose=False)
            if reply and ARP in reply and reply[ARP].op == 2:
                print(f'{ip} 在线，MAC 地址: {reply[ARP].hwsrc}')
        except Exception as e:
            continue


def scapy_port(ip, start_port=20, end_port=100, src_ip='192.168.10.101'):
    for port in range(start_port, end_port + 1):
        try:
            pkg = IP(src=src_ip, dst=ip) / TCP(dport=port, flags='S')
            reply = sr1(pkg, timeout=1, verbose=False)
            if reply and reply.haslayer(TCP) and reply[TCP].flags == 0x12:  # SYN/ACK
                print(f'端口 {port} 开放')
                # 发送 RST 包关闭连接
                rst = IP(src=src_ip, dst=ip) / TCP(dport=port, flags='R', seq=reply[TCP].ack)
                send(rst, verbose=False)
        except Exception as e:
            continue


def scapy_tcp_handshake(ip, dst_port=55555, src_port=None):
    if src_port is None:
        src_port = random.randint(1024, 65535)

    # 第一次握手
    pkg_1 = IP(dst=ip) / TCP(sport=src_port, dport=dst_port, flags='S')
    reply = sr1(pkg_1, timeout=2, verbose=False)

    if not reply or not reply.haslayer(TCP) or reply[TCP].flags != 0x12:  # SYN/ACK
        print("未收到 SYN/ACK 响应或响应不完整")
        return

    # 第二次握手
    seq_ack = reply[TCP].ack
    ack_seq = reply[TCP].seq + 1
    pkg_2 = IP(dst=ip) / TCP(sport=src_port, dport=dst_port, flags='A', seq=ack_seq, ack=seq_ack)
    send(pkg_2, verbose=False)

    print("三次握手成功，开始发送聊天信息...")

    while True:
        message = input("输入消息发送 (或 'exit' 退出): ")
        if message.lower() == 'exit':
            break
        pkg_chat = IP(dst=ip) / TCP(sport=src_port, dport=dst_port, flags='PA', seq=ack_seq, ack=seq_ack) / message
        reply = sr1(pkg_chat, timeout=2, verbose=False)

        if reply and reply.haslayer(TCP) and reply[TCP].flags == 0x10:  # ACK
            ack_seq += len(message)
            try:
                received = reply[Raw].load.decode('utf-8')
                print(f"收到响应: {received}")
            except UnicodeDecodeError:
                print("收到的响应无法解码为 UTF-8")
        elif reply is None:
            print("未收到响应")
        else:
            print("握手失败或连接关闭")


def parse_arguments():
    parser = argparse.ArgumentParser(description="Scapy 网络工具集", formatter_class=argparse.RawTextHelpFormatter)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--arp", action="store_true", help="执行 ARP 扫描")
    group.add_argument("--port", action="store_true", help="执行端口扫描")
    group.add_argument("--tcp", action="store_true", help="执行 TCP 三次握手及聊天")

    parser.add_argument("--ip", type=str, required=True, help="目标 IP 地址或网段（例如 192.168.10.1 或 192.168.10.0/24）")

    parser.add_argument("--start-port", type=int, default=20, help="端口扫描起始端口（默认: 20）")
    parser.add_argument("--end-port", type=int, default=100, help="端口扫描结束端口（默认: 100）")
    parser.add_argument("--dst-port", type=int, default=55555, help="TCP 目标端口（默认: 55555）")

    return parser.parse_args()


def main():
    args = parse_arguments()

    if args.arp:
        if '/' in args.ip:
            # 处理网段
            network, mask = args.ip.split('/')
            start_ip = int(network.split('.')[-1])
            end_ip = start_ip + (0xFFFFFFFF << (32 - int(mask))) - 1
            scapy_ip(start=start_ip, end=end_ip - start_ip + 1, network=f"{network}.{start_ip // 256}.{start_ip % 256}.")
        else:
            scapy_ip(start=int(args.ip.split('.')[-1]), network=args.ip.rsplit('.', 1)[0] + '.')

    if args.port:
        if '/' in args.ip:
            print("端口扫描不支持网段，请提供一个单一的IP地址。")
        else:
            scapy_port(args.ip, args.start_port, args.end_port)

    if args.tcp:
        if '/' in args.ip:
            print("TCP 握手不支持网段，请提供一个单一的IP地址。")
        else:
            scapy_tcp_handshake(args.ip, args.dst_port)


if __name__ == '__main__':
    main()
