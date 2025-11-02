#include "ip.h"

#include "arp.h"
#include "ethernet.h"
#include "icmp.h"
#include "net.h"

/**
 * @brief 处理一个收到的数据包
 *
 * @param buf 要处理的数据包
 * @param src_mac 源mac地址
 */
void ip_in(buf_t *buf, uint8_t *src_mac) {
    // 检查数据包长度
    if (buf->len < sizeof(ip_hdr_t)) {
        return;
    }
    buf_t copy_buf;
    buf_init(&copy_buf, buf->len);
    memcpy(copy_buf.data, buf->data, buf->len);
    copy_buf.len = buf->len;
    // 进行报文头部检测
    ip_hdr_t *ip_hdr = (ip_hdr_t *)buf->data;
    if (ip_hdr->version != IP_VERSION_4) {
        return;
    }
    if (swap16(ip_hdr->total_len16) > buf->len) {
        return;
    }

    // checksum
    uint16_t received_checksum = ip_hdr->hdr_checksum16;
    ip_hdr->hdr_checksum16 = 0;
    uint16_t calculated_checksum = checksum16((uint16_t *)ip_hdr, sizeof(ip_hdr_t));
    if (received_checksum != calculated_checksum) {
        return;
    }
    ip_hdr->hdr_checksum16 = received_checksum;

    // dst_ip是否是本机ip
    if (memcmp(ip_hdr->dst_ip, net_if_ip, NET_IP_LEN) != 0) {
        return;
    }

    // remove padding
    if (buf->len > swap16(ip_hdr->total_len16)) {
        buf_remove_padding(buf, buf->len - swap16(ip_hdr->total_len16));
    }

    // remove the ip header
    buf_remove_header(buf, ip_hdr->hdr_len * IP_HDR_LEN_PER_BYTE);

    // give the payload to upper layer
    uint8_t protocol = ip_hdr->protocol;
    uint8_t *src_ip = ip_hdr->src_ip;
    if (net_in(buf, protocol, src_ip) < 0) {
        // ICMP
        icmp_unreachable(&copy_buf, src_ip, ICMP_CODE_PROTOCOL_UNREACH);
        return;
    }
    
}
/**
 * @brief 处理一个要发送的ip分片
 *
 * @param buf 要发送的分片
 * @param ip 目标ip地址
 * @param protocol 上层协议
 * @param id 数据包id
 * @param offset 分片offset，必须被8整除
 * @param mf 分片mf标志，是否有下一个分片
 */
void ip_fragment_out(buf_t *buf, uint8_t *ip, net_protocol_t protocol, int id, uint16_t offset, int mf) {
    // add ip header buffer
    buf_add_header(buf, sizeof(ip_hdr_t));

    // fill the ip header
    ip_hdr_t *ip_hdr = (ip_hdr_t *)buf->data;
    ip_hdr->version = IP_VERSION_4;
    ip_hdr->hdr_len = sizeof(ip_hdr_t) / IP_HDR_LEN_PER_BYTE;
    ip_hdr->tos = 0;
    ip_hdr->total_len16 = swap16(buf->len);
    ip_hdr->id16 = swap16((uint16_t)id);
    ip_hdr->flags_fragment16 = swap16((mf ? IP_MORE_FRAGMENT : 0) | offset);
    ip_hdr->ttl = IP_DEFALUT_TTL;
    ip_hdr->protocol = (uint8_t)protocol;
    memcpy(ip_hdr->src_ip, net_if_ip, NET_IP_LEN);
    memcpy(ip_hdr->dst_ip, ip, NET_IP_LEN);

    // checksum
    ip_hdr->hdr_checksum16 = 0;
    uint16_t checksum16_result = checksum16((uint16_t *)ip_hdr, sizeof(ip_hdr_t));
    ip_hdr->hdr_checksum16 = checksum16_result;

    // send to ethernet layer
    arp_out(buf, ip);
}

/**
 * @brief 处理一个要发送的ip数据包
 *
 * @param buf 要处理的包
 * @param ip 目标ip地址
 * @param protocol 上层协议
 */
void ip_out(buf_t *buf, uint8_t *ip, net_protocol_t protocol) {
    // check whether need fragment
    int mtu = ETHERNET_MAX_TRANSPORT_UNIT - sizeof(ip_hdr_t);
    static int id = 0; 
    if (buf->len <= mtu) {
        // no fragment
        buf_t ip_buf;
        buf_init(&ip_buf, buf->len);
        memcpy(ip_buf.data, buf->data, buf->len);
        ip_buf.len = buf->len;
        ip_fragment_out(&ip_buf, ip, protocol, id, 0, 0);
        id++;
        return;
    }
    int i;
    // 最后一个数据包需要特殊处理
    for (i = 0; i * mtu + mtu < buf->len; i ++) {
        // fragment and send
        buf_t fragment_buf;
        // init 
        buf_init(&fragment_buf, mtu);
        // cut
        memcpy(fragment_buf.data, buf->data + i * mtu, mtu);
        fragment_buf.len = mtu;
        // deal with each fragment
        ip_fragment_out(&fragment_buf, ip, protocol, id, i * mtu / 8, 1);
    }
    // deal with the one mtu
    buf_t last_buf;
    buf_init(&last_buf, buf->len - i * mtu);
    memcpy(last_buf.data, buf->data + i * mtu, buf->len - i * mtu);
    last_buf.len = buf->len - i * mtu;
    ip_fragment_out(&last_buf, ip, protocol, id, i * mtu / 8, 0);
    id++;
    return;
}

/**
 * @brief 初始化ip协议
 *
 */
void ip_init() {
    net_add_protocol(NET_PROTOCOL_IP, ip_in);
}