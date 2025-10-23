#include "driver.h"
#include "net.h"

#ifdef TCP
#include "tcp.h"
void tcp_handler(tcp_conn_t *tcp_conn, uint8_t *data, size_t len, uint8_t *src_ip, uint16_t src_port) {
    for (int i = 0; i < len; i++)
        putchar(data[i]);
    if (len)
        putchar('\n');
    fflush(stdout);

    tcp_send(tcp_conn, data, len, 60000, src_ip, src_port);  // 发送tcp包
}
#endif

int main(int argc, char const *argv[]) {
    if (net_init() == -1) {  // 初始化协议栈
        printf("net init failed.");
        return -1;
    }

#ifdef TCP
    tcp_open(60000, tcp_handler);  // 注册端口的tcp监听回调
#endif

    while (1) {
        net_poll();  // 一次主循环
    }

    return 0;
}
