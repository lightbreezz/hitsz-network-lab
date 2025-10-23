#ifndef UDP_H
#define UDP_H

#include "net.h"

#pragma pack(1)
typedef struct udp_hdr {
    uint16_t src_port16;   // 源端口
    uint16_t dst_port16;   // 目标端口
    uint16_t total_len16;  // 整个数据包的长度
    uint16_t checksum16;   // 校验和
} udp_hdr_t;
#pragma pack()

typedef void (*udp_handler_t)(uint8_t *data, size_t len, uint8_t *src_ip, uint16_t src_port);

void udp_init();
void udp_in(buf_t *buf, uint8_t *src_ip);
void udp_out(buf_t *buf, uint16_t src_port, uint8_t *dst_ip, uint16_t dst_port);
void udp_send(uint8_t *data, uint16_t len, uint16_t src_port, uint8_t *dst_ip, uint16_t dst_port);
int udp_open(uint16_t port, udp_handler_t handler);
void udp_close(uint16_t port);
#endif