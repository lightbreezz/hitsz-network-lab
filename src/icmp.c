#include "icmp.h"

#include "ip.h"
#include "net.h"

/**
 * @brief 发送icmp响应
 *
 * @param req_buf 收到的icmp请求包
 * @param src_ip 源ip地址
 */
static void icmp_resp(buf_t *req_buf, uint8_t *src_ip) {
    // init buf
    buf_t txbuf;
    buf_init(&txbuf, req_buf->len);
    // fill the icmp header and payload
    memcpy(txbuf.data, req_buf->data, req_buf->len);
    icmp_hdr_t *tx_icmp_hdr = (icmp_hdr_t *)txbuf.data;
    icmp_hdr_t *req_icmp_hdr = (icmp_hdr_t *)req_buf->data;
    tx_icmp_hdr->type = ICMP_TYPE_ECHO_REPLY;
    // 查看协议可以知道写0
    tx_icmp_hdr->code = 0;
    tx_icmp_hdr->id16 = req_icmp_hdr->id16;
    tx_icmp_hdr->seq16 = req_icmp_hdr->seq16;
    // checksum
    tx_icmp_hdr->checksum16 = 0;
    uint16_t checksum16_result = checksum16((uint16_t *)txbuf.data, txbuf.len);
    tx_icmp_hdr->checksum16 = checksum16_result;

    // send to ip layer
    ip_out(&txbuf, src_ip, NET_PROTOCOL_ICMP);
}

/**
 * @brief 处理一个收到的数据包
 *
 * @param buf 要处理的数据包
 * @param src_ip 源ip地址
 */
void icmp_in(buf_t *buf, uint8_t *src_ip) {
    // check the length
    if (buf->len < sizeof(icmp_hdr_t)) {
        return;
    }
    // check the type
    icmp_hdr_t *icmp_hdr = (icmp_hdr_t *)buf->data;
    if (icmp_hdr->type == ICMP_TYPE_ECHO_REQUEST) {
        // ICMP Echo Reply
        icmp_resp(buf, src_ip);
        return;
    }
}

/**
 * @brief 发送icmp不可达
 *
 * @param recv_buf 收到的ip数据包
 * @param src_ip 源ip地址
 * @param code icmp code，协议不可达或端口不可达
 */
void icmp_unreachable(buf_t *recv_buf, uint8_t *src_ip, icmp_code_t code) {
    // init buf
    buf_t txbuf;
    buf_init(&txbuf, sizeof(icmp_hdr_t) + sizeof(ip_hdr_t) + 8);
    // fill the icmp header
    icmp_hdr_t *icmp_hdr = (icmp_hdr_t *)txbuf.data;
    icmp_hdr->type = ICMP_TYPE_UNREACH;
    icmp_hdr->code = code;
    icmp_hdr->id16 = 0;
    icmp_hdr->seq16 = 0;
    // fill the IP header and first 8 bytes of payload
    ip_hdr_t *ip_hdr = (ip_hdr_t *)(icmp_hdr + 1);
    ip_hdr_t *recv_ip_hdr = (ip_hdr_t *)recv_buf->data;
    memcpy(ip_hdr, recv_ip_hdr, sizeof(ip_hdr_t));
    uint8_t *data = (uint8_t *)(ip_hdr + 1);
    uint8_t *recv_data = (uint8_t *)(recv_ip_hdr + 1);
    memcpy(data, recv_data, 8);
    // checksum
    icmp_hdr->checksum16 = 0;
    uint16_t checksum16_result = checksum16((uint16_t *)txbuf.data, txbuf.len);
    icmp_hdr->checksum16 = checksum16_result;

    // send to ip layer
    ip_out(&txbuf, src_ip, NET_PROTOCOL_ICMP);
}

/**
 * @brief 初始化icmp协议
 *
 */
void icmp_init() {
    net_add_protocol(NET_PROTOCOL_ICMP, icmp_in);
}