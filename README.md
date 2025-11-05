# HITSZ Net (轻量网络协议栈)

一个用于教学与测试的轻量级网络协议栈实现，包含以太网/ARP/IP/ICMP/UDP/TCP 的基本实现，并带有测试套件与示例应用（web/tcp/udp server）。

## 主要入口与参考文件
- 构建配置：[CMakeLists.txt](CMakeLists.txt) / [Makefile](Makefile)
- 核心代码（协议实现）：[src/](src/)
  - 协议栈初始化与调度：[`net_init`](src/net.c)、[`net_poll`](src/net.c) — [src/net.c](src/net.c)
  - 驱动层：[`driver_open`](src/driver.c) — [src/driver.c](/src/driver.c)；测试 faker 驱动：[`driver_recv`](testing/faker/driver.c) — [testing/faker/driver.c](testing/faker/driver.c)
  - UDP：[`udp_open`](src/udp.c)、[`udp_send`](src/udp.c) — [src/udp.c](src/udp.c)
  - TCP：[`tcp_open`](src/tcp.c)、[`tcp_send`](src/tcp.c) — [src/tcp.c](src/tcp.c)
  - 实用函数：[`iptos`](src/utils.c)、[`timetos`](src/utils.c) — [src/utils.c](src/utils.c)
- 头文件：[include/](include/)
  - 网络抽象：[include/net.h](include/net.h)
  - TCP/UDP/ICMP 定义：[include/tcp.h](include/tcp.h)、[include/udp.h](include/udp.h)、[include/icmp.h](include/icmp.h)
  - 工具与校验：[include/utils.h](include/utils.h)
- 示例应用：
  - Web 服务器：[`http_request_handler`](app/web_server.c) — [app/web_server.c](app/web_server.c)
  - TCP 回显服务器：[app/tcp_server.c](app/tcp_server.c)
  - UDP 回显服务器：[app/udp_server.c](app/udp_server.c)
- 测试与数据：
  - 测试代码：`testing/` 目录（多个测试用例，例如 [testing/ip_test.c](testing/ip_test.c)、[testing/udp_test.c](testing/udp_test.c)）
  - PCAP 数据：`testing/data/` 子目录
- 第三方：内置了 Npcap/libpcap 头文件（例如 [Npcap/Include/pcap/pcap.h](Npcap/Include/pcap/pcap.h)）

## 快速构建
1. 使用 CMake（推荐）
   ```sh
   mkdir -p build
   cmake -B build -S .
   cmake --build build
   ```
2. 或使用仓库中的 Makefile
   ```sh
   make build
   ```

## 运行示例
- 运行 web 服务器：
  ```sh
   ./build/web_server
  ```
  或运行 TCP/UDP 示例：
  ```sh
   ./build/tcp_server
   ./build/udp_server
  ```

## 运行测试
- 在构建目录执行 ctest：
  ```sh
  cd build
  ctest --output-on-failure
  ```

## 使用辅助脚本（发送测试包）
- 持续发送脚本：test_continuely.py
- 单条消息发送：test_one_message.py
- 注意：这些脚本依赖 Scapy，需要 root 权限运行（见脚本开头的说明）。

## 依赖
- libpcap（Linux/macOS）或 Npcap（Windows）。头/库位置通过 CMake 配置查找（项目内包含了 Npcap 的头文件目录）。
- 构建工具：cmake、make、gcc/clang

## 开发提示
- 新协议/处理器请在协议表注册（查看 net.c）。
- 应用层回调示例见 app/web_server.c、app/tcp_server.c、app/udp_server.c。
- 驱动抽象在 driver.h 中。测试环境使用 driver.c 通过 pcap 回放数据。

## 代码导航（常用文件）
- 项目根：CMakeLists.txt / Makefile
- 源码：src
- 头文件：include
- 应用：app
- 测试：testing
- 测试数据：data
- Npcap 头文件（已包含）：Npcap/Include/pcap/pcap.h

## 致谢
感谢老师的支持与鼓励，做完一整套协议栈收获很多！

