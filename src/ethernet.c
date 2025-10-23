#include "ethernet.h"

#include "arp.h"
#include "driver.h"
#include "ip.h"
#include "utils.h"
/**
 * @brief 处理一个收到的数据包
 *
 * @param buf 要处理的数据包
 */
void ethernet_in(buf_t *buf) {
    // 1. judge the data-len
    if (buf->len < sizeof(ether_hdr_t)) {
        // 数据包长度小于以太网头部长度，丢弃
        return;
    }
    // 2. parser
    // 处理时首先要转换
    ether_hdr_t *hdr = (ether_hdr_t *)buf->data;
    // 处理上层协议
    net_protocol_t protocol = swap16(hdr->protocol16);
    uint8_t *src = hdr->src;
    buf_remove_header(buf, sizeof(ether_hdr_t));
    // send to upper layer
    net_in(buf, protocol, src);
}
/**
 * @brief 处理一个要发送的数据包
 *
 * @param buf 要处理的数据包
 * @param mac 目标MAC地址
 * @param protocol 上层协议
 */
void ethernet_out(buf_t *buf, const uint8_t *mac, net_protocol_t protocol) {
    // 1. judge the data-len
    if (buf->len < 46){
        size_t padding = 46 - buf->len;
        buf_add_padding(buf, padding);
    }
    // 2. ADD the header
    buf_add_header(buf, sizeof(ether_hdr_t));
    ether_hdr_t *hdr = (ether_hdr_t *)buf->data;
    // 3. add the dst mac
    memcpy(hdr->dst, mac, NET_MAC_LEN);

    // 4. add the src mac
    memcpy(hdr->src, net_if_mac, NET_MAC_LEN);

    // 5. add the protocol
    // 需要转换为大端序
    hdr->protocol16 = swap16(protocol);

    // 6. send to the driver
    driver_send(buf);

}
/**
 * @brief 初始化以太网协议
 *
 */
void ethernet_init() {
    buf_init(&rxbuf, ETHERNET_MAX_TRANSPORT_UNIT + sizeof(ether_hdr_t));
}

/**
 * @brief 一次以太网轮询
 *
 */
void ethernet_poll() {
    if (driver_recv(&rxbuf) > 0)
        ethernet_in(&rxbuf);
}
