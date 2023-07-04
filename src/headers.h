/**
 * @file headers.h
 * @author your name (you@domain.com)
 * @brief 
 * @version 0.1
 * @date 2023-06-30
 * 
 * @copyright Copyright (c) 2023
 * 
 */

#ifndef SRC_HEADERS_H_
#define SRC_HEADERS_H_

#include <unistd.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <net/ethernet.h>

namespace net_io_top {

/**
 * @brief Ethernet 报头
 * 
 */
struct sniff_ethernet {
    u_char ether_dhost[ETHER_ADDR_LEN];
    u_char ether_shost[ETHER_ADDR_LEN];
    u_short ether_type;
};

/**
 * @brief IP 报头
 * 
 */
struct sniff_ip {
    u_int ip_hl:4, ip_v:4;
    u_char ip_tos;
    u_short ip_len;
    u_short ip_id;
    u_short ip_off;
    u_char ip_ttl;
    u_char ip_p;
    u_short ip_sum;
    struct in_addr ip_src, ip_dst;
};

/**
 * @brief TCP 报头
 * 
 */
struct sniff_tcp {
    // source port
    u_short th_sport;
    // destination port
    u_short th_dport;
    // sequence number
    tcp_seq th_seq;
    // acknowledgment number
    tcp_seq th_ack;
    // th_x2(unused), th_off(data offset)
    // 暂时先不兼容大端模式，只处理小端模式
    u_int th_x2:4, th_off:4;
    u_char th_flags;
    // window
    u_short th_win;
    // checksum
    u_short th_sum;
    // urgent pointer
    u_short th_urp;
};

}  // namespace net_io_top

#endif  // SRC_HEADERS_H_
