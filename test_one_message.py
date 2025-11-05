# 每次发送一条消息
from scapy.all import Ether, IP, UDP, Raw, sendp, TCP, RandShort
while True:
    message = input("Enter message to send: ")
    if message.lower() in ['quit', 'exit', 'q']:
        print("程序退出")
        break
    pkt = Ether(dst="00:11:22:33:44:55")/IP(dst="10.250.111.71")/TCP(dport=60000, sport=RandShort(), flags="S")/Raw(message.encode())
    sendp(pkt, iface="en0", verbose=1)
