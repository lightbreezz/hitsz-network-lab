from scapy.all import Ether, IP, UDP, Raw, sendp
# 把 AA:BB:CC:DD:EE:FF 换成 en0 的 MAC
# pkt = Ether(dst="00:11:22:33:44:55")/IP(dst="10.250.111.71")/UDP(dport=60000, sport=50000)/Raw(b"I like hitsz")
pkt = Ether(dst="00:11:22:33:44:55")/IP(dst="10.250.111.71")/UDP(dport=60000, sport=50000)/Raw(b"I like networking")
sendp(pkt, iface="en0", verbose=1)