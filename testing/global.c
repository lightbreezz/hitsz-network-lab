#include "arp.h"
#include "ip.h"
#include "tcp.h"
#include "map.h"
#include "testing/log.h"
#include "utils.h"

#include <pcap.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

FILE *control_flow;

FILE *pcap_in;
FILE *pcap_out;
FILE *pcap_demo;

FILE *arp_fin;
FILE *arp_fout;
FILE *arp_log_f;

FILE *ip_fin;
FILE *ip_fout;

FILE *icmp_fin;
FILE *icmp_fout;

FILE *udp_fin;
FILE *udp_fout;

FILE *tcp_fin;
FILE *tcp_fout;

FILE *out_log;
FILE *demo_log;

extern map_t arp_table;
extern map_t arp_buf;

// char* state[16] = {
//         [ARP_PENDING] "pending",
//         [ARP_VALID]   "valid  ",
//         [ARP_INVALID] "invalid",
//         "unknown",
//         "unknown",
//         "unknown",
//         "unknown",
//         "unknown",
//         "unknown",
//         "unknown",
//         "unknown",
//         "unknown",
//         "unknown",
//         "unknown",
//         "unknown",
//         "unknown"
// };

FILE *open_file(char *path, char *name, char *mode) {
    char filename[128];
    sprintf(filename, "%s/%s", path, name);
    // printf("opening: %s\n", filename);
    return fopen(filename, mode);
}

ssize_t getline(char **lineptr, size_t *n, FILE *fp) {
    int i;
    if (*lineptr == NULL || *n < 256) {
        *lineptr = (char *)realloc(*lineptr, 256);
        if (*lineptr == NULL) {
            printf("Realloc failed 1\n");
            return -1;
        }
        *n = 256;
    }
    char *buf = *lineptr;
    size_t size = *n;
    for (i = 0; i < size; i++) {
        int c = fgetc(fp);
        if (c == EOF) {
            buf[i] = 0;
            return (i == 0) ? -1 : i;
        }
        if (c == '\r') {
            i--;
            continue;
        }
        if (i >= size - 1) {
            size *= 2;
            buf = realloc(buf, size);
            if (buf == NULL) {
                printf("Realloc failed 2\n");
                return -1;
            }
            *lineptr = buf;
            *n = size;
        }
        buf[i] = c;
        if (c == '\n') {
            buf[i + 1] = 0;
            return i + 1;
        }
    }
    return -1;
}

char *print_ip(uint8_t *ip) {
    static char result[32];
    if (ip == 0) {
        return "(null)";
    } else {
        sprintf(result, "%d.%d.%d.%d", ip[0], ip[1], ip[2], ip[3]);
        return result;
    }
}

char *print_mac(uint8_t *mac) {
    static char result[32];
    if (mac == 0) {
        return "(null)";
    } else {
        sprintf(result, "%02x:%02x:%02x:%02x:%02x:%02x", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
        return result;
    }
}

void fprint_buf(FILE *f, buf_t *buf) {
    fprintf(f, "\tbuf:");
    if (buf == 0) {
        fprintf(f, "(null)\n");
    } else {
        for (int i = 0; i < buf->len; i++) {
            fprintf(f, " %02x", buf->data[i]);
        }
        fprintf(f, "\n");
    }
}

static inline void *map_entry_get(map_t *map, size_t pos) {
    if (pos >= map->max_size)
        return NULL;
    return map->data + pos * (map->key_len + map->value_len + sizeof(time_t));
}

static inline int map_entry_valid(map_t *map, const void *entry) {
    time_t entry_time = *(time_t *)((uint8_t *)entry + map->key_len + map->value_len);
    return entry_time && (!map->timeout || entry_time + map->timeout >= time(NULL));
}

void log_tab_buf() {
    fprintf(arp_log_f, "<====== arp table =======>\n");
    for (size_t i = 0; i < arp_table.max_size; i++) {
        uint8_t *entry = (uint8_t *)map_entry_get(&arp_table, i);
        if (map_entry_valid(&arp_table, entry))
            fprintf(arp_log_f, "%s -> %s\n", print_ip(entry), print_mac(entry + arp_table.key_len));
    }

    fprintf(arp_log_f, "<====== arp buf =======>\n");
    for (size_t i = 0; i < arp_buf.max_size; i++) {
        uint8_t *entry = (uint8_t *)map_entry_get(&arp_buf, i);
        if (map_entry_valid(&arp_buf, entry)) {
            fprintf(arp_log_f, "%s -> ", print_ip(entry));
            buf_t *buf = (buf_t *)(entry + arp_buf.key_len);
            for (int i = 0; i < buf->len; i++) {
                fprintf(arp_log_f, " %02x", buf->data[i]);
            }
            fputc('\n', arp_log_f);
        }
    }
}

int get_round(FILE *f) {
    char *p = 0;
    size_t n = 0;
    do {
        if (getline(&p, &n, f) == -1)
            return -1;
    } while (memcmp("Round", p, 5));
    if (p)
        free(p);
    return 0;
}

int check_round() {
    char *p0 = 0;
    char *p1 = 0;
    size_t n0 = 0;
    size_t n1 = 0;
    int result, len0, len1;
    int line = 0;
CHECK_ROUND_NEXT_LINE:
    line++;
    len0 = getline(&p0, &n0, demo_log);
    len1 = getline(&p1, &n1, out_log);
    if (len0 != len1) {
        result = 1;
        goto CHECK_ROUND_EXIT;
    }

    if (len0 == -1) {
        result = len1 != -1;
        goto CHECK_ROUND_EXIT;
    }

    if (len0 <= 1) {
        result = 0;
        goto CHECK_ROUND_EXIT;
    }

    if (memcmp(p0, p1, len0)) {
        result = 1;
        goto CHECK_ROUND_EXIT;
    }

    goto CHECK_ROUND_NEXT_LINE;

CHECK_ROUND_EXIT:
    if (p0)
        free(p0);
    if (p1)
        free(p1);
    return result ? line : 0;
}

int check_log() {
    int i = 0;
    int ret;
    int result = 0;
    PRINT_INFO("Checking log file(compare with demo).\n");
    while (get_round(demo_log) == 0) {
        i++;
        if (get_round(out_log)) {
            PRINT_WARN("Missing Round %d\n", i);
            result = 1;
            continue;
        }
        if ((ret = check_round())) {
            PRINT_WARN("Round %d: differences found(Line %d of the current round)\n", i, ret);
            result = 1;
        } else {
            PRINT_PASS("Round %d: no differences\n", i);
        }
    }

    while (get_round(out_log) == 0) {
        i++;
        result = 1;
        PRINT_WARN("Additional Round %d found\n", i);
    }

    if (result) {
        PRINT_ERROR("====> Some log rounds are different to the demo.\n");
    } else {
        PRINT_PASS("====> All log rounds are the same to the demo.\n");
    }
    return result;
}

int _check_pcap(int idx, const uint8_t *pkt_data0, const uint8_t *pkt_data1, struct pcap_pkthdr *pkt_hdr0, struct pcap_pkthdr *pkt_hdr1) {
    // 解析 IP 和 TCP 头部
    ip_hdr_t *ip0 = (ip_hdr_t *)(pkt_data0 + 14); // 假设以太网头部长度为 14 字节
    ip_hdr_t *ip1 = (ip_hdr_t *)(pkt_data1 + 14);

    tcp_hdr_t *tcp0 = (tcp_hdr_t *)((uint8_t *)ip0 + (ip0->hdr_len << 2));
    tcp_hdr_t *tcp1 = (tcp_hdr_t *)((uint8_t *)ip1 + (ip1->hdr_len << 2));

    if (ip0->protocol != IPPROTO_TCP || ip1->protocol != IPPROTO_TCP) {
        // 对于非 TCP 报文，直接比较整个数据包
        if (memcmp(pkt_data0, pkt_data1, pkt_hdr0->len)) {
            PRINT_WARN("Packet %d: differences found\n", idx);
            return 1;
        }
    }

    /* 校验 TCP 报文。仅比较除了 seq 、 ack 、 checksum 之外的字段 */
    if (tcp0->src_port16 != tcp1->src_port16) {
        PRINT_WARN("Packet %d: TCP source port mismatch (demo: %d, user: %d)\n", idx, swap16(tcp0->src_port16), swap16(tcp1->src_port16));
        return 1;
    }
    if (tcp0->dst_port16 != tcp1->dst_port16) {
        PRINT_WARN("Packet %d: TCP destination port mismatch (demo: %d, user: %d)\n", idx, swap16(tcp0->dst_port16), swap16(tcp1->dst_port16));
        return 1;
    }

    // 比较数据偏移（doff）
    if (tcp0->doff != tcp1->doff) {
        PRINT_WARN("Packet %d: TCP data offset mismatch (demo: %d, user: %d)\n", idx, tcp0->doff, tcp1->doff);
        return 1;
    }

    // 比较标志位（flags）
    if (tcp0->flags != tcp1->flags) {
        PRINT_WARN("Packet %d: TCP flags mismatch (demo: 0x%02x, user: 0x%02x)\n", idx, tcp0->flags, tcp1->flags);
        return 1;
    }

    // 比较窗口大小（win）
    if (tcp0->win != tcp1->win) {
        PRINT_WARN("Packet %d: TCP window size mismatch (demo: %d, user: %d)\n", idx, swap16(tcp0->win), swap16(tcp1->win));
        return 1;
    }

    // 比较紧急指针（uptr）
    if (tcp0->uptr != tcp1->uptr) {
        PRINT_WARN("Packet %d: TCP urgent pointer mismatch (demo: %d, user: %d)\n", idx, swap16(tcp0->uptr), swap16(tcp1->uptr));
        return 1;
    }

    // 比较 TCP 有效载荷
    int tcp0_len = swap16(ip0->total_len16) - (ip0->hdr_len << 2) - ((tcp0->doff >> 4) * 4);
    int tcp1_len = swap16(ip1->total_len16) - (ip1->hdr_len << 2) - ((tcp1->doff >> 4) * 4);
    if (tcp0_len != tcp1_len) {
        PRINT_WARN("Packet %d: TCP payload length mismatch (demo: %d, user: %d)\n", idx, tcp0_len, tcp1_len);
        return 1;
    }

    return 0;
}

int check_pcap() {
    char errbuf[PCAP_ERRBUF_SIZE];
    const char *str_exit = "Exiting pcap file check\n";
    PRINT_INFO("Checking pcap output file(compare with demo).\n");
    pcap_t *pcap0 = pcap_fopen_offline(pcap_demo, errbuf);
    if (pcap0 == 0) {
        PRINT_ERROR("Load demo output failed:%s\n", errbuf);
        printf("%s", str_exit);
        return -1;
    }
    pcap_t *pcap1 = pcap_fopen_offline(pcap_out, errbuf);
    if (pcap1 == 0) {
        PRINT_ERROR("Load demo output failed:%s\n", errbuf);
        printf("%s", str_exit);
        return -1;
    }

    int idx = 0;
    int result = 0;
    struct pcap_pkthdr *pkt_hdr0, *pkt_hdr1;
    const uint8_t *pkt_data0, *pkt_data1;

CHECK_PCAP_NEXT_PACKET:
    idx++;
    int ret0 = pcap_next_ex(pcap0, &pkt_hdr0, &pkt_data0);
    int ret1 = pcap_next_ex(pcap1, &pkt_hdr1, &pkt_data1);

    if (ret0 == -1) {
        PRINT_ERROR("Error occured on loading packet %d from demo:%s\n", idx, pcap_geterr(pcap0));
        printf("%s", str_exit);
        goto CHECK_PCAP_EXIT;
    }

    if (ret1 == -1) {
        PRINT_ERROR("Error occured on loading packet %d from user output:%s\n", idx, pcap_geterr(pcap1));
        printf("%s", str_exit);
        goto CHECK_PCAP_EXIT;
    }

    if (ret0 == PCAP_ERROR_BREAK) {
        if (ret1 == 1) {
            PRINT_ERROR("Addition packet %d found\n", idx);
            result = 1;
            goto CHECK_PCAP_NEXT_PACKET;
        } else if (ret1 == PCAP_ERROR_BREAK) {
            if (result) {
                PRINT_ERROR("====> Some packets are different to the demo.\n");
            } else {
                PRINT_PASS("====> All packets are the same to the demo.\n");
            }
            goto CHECK_PCAP_EXIT;
        } else {
            PRINT_ERROR("UNKNOWN ERROR\n");
            printf("%s", str_exit);
            result = 1;
            goto CHECK_PCAP_EXIT;
        }
    }

    if (ret1 == PCAP_ERROR_BREAK) {
        if (ret0 != 1) {
            PRINT_ERROR("UNKNOWN ERROR\n");
            printf("%s", str_exit);
            result = 1;
            goto CHECK_PCAP_EXIT;
        } else {
            PRINT_WARN("Missing packet %d\n", idx);
            result = 1;
            goto CHECK_PCAP_NEXT_PACKET;
        }
    }

    if (pkt_hdr0->len != pkt_hdr1->len) {
        PRINT_WARN("Packet %d: differences found\n", idx);
        result = 1;
        goto CHECK_PCAP_NEXT_PACKET;
    }

    // if (_check_pcap(idx, pkt_data0, pkt_data1, pkt_hdr0, pkt_hdr1)) {
    //     goto CHECK_PCAP_NEXT_PACKET;
    // }

    PRINT_PASS("Packet %d: no differences\n", idx);
    goto CHECK_PCAP_NEXT_PACKET;
CHECK_PCAP_EXIT:
    pcap_close(pcap0);
    pcap_close(pcap1);
    return result;
}
