# 持续发送消息
from scapy.all import srp1, sendp, Ether, IP, TCP, getmacbyip
import os

iface = "en0"
dst_ip = "10.250.111.71"
dst_port = 60000
sport = 12345

if os.geteuid() != 0:
    raise SystemExit("请以 root/sudo 运行此脚本")

dst_mac = getmacbyip(dst_ip)
if not dst_mac:
    raise SystemExit(f"无法通过 ARP 获取 {dst_ip} 的 MAC，请检查子网/路由/交换机配置")

# 三次握手
client_isn = 1000
syn = Ether(dst=dst_mac)/IP(dst=dst_ip)/TCP(dport=dst_port, sport=sport, flags="S", seq=client_isn)
synack = srp1(syn, iface=iface, timeout=2, verbose=0)
if synack is None or not synack.haslayer(TCP) or (synack.getlayer(TCP).flags & 0x12) == 0:
    print("no syn/ack, abort")
    raise SystemExit(1)

# 完成握手，初始化 seq/ack
seq = client_isn + 1
ack = synack.seq + 1
# 发送 ACK 完成握手
ack_pkt = Ether(dst=dst_mac)/IP(dst=dst_ip)/TCP(dport=dst_port, sport=sport, flags="A", seq=seq, ack=ack)
sendp(ack_pkt, iface=iface, verbose=0)

# 发送应用数据：每发送一次更新 seq
while True:
    msg = input("Enter message: ")
    if msg.lower() in ("quit","exit","q"):
        break
    payload = msg.encode()
    psh = Ether(dst=dst_mac)/IP(dst=dst_ip)/TCP(dport=dst_port, sport=sport, flags="PA", seq=seq, ack=ack)/payload
    sendp(psh, iface=iface, verbose=0)
    seq += len(payload)  