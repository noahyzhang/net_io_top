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

// IP 协议报头长度
#define IP_HEADER_LEN 20
// TCP 协议报头长度
#define TCP_HEADER_LEN 20
// 链路层 DLT_EN10MB (以太网)协议头部，占用 14 字节
// 包括：目的 MAC 地址(6字节)、源 MAC 地址(6字节)、类型/长度字段(2字节)
// 注意其中有一个可选的 802.1q 标识，占用 4 字节
#define DLT_EN10MB_HEADER_LEN 14
// 链路层 DLT_LINUX_SLL (Linux socket) 协议头部，占用 16 字节
// 包括：数据包类型(2 字节)、链路层设备类型(2 字节)、链路层地址长度(2 字节)、链路层上层协议(2 字节)、链路层地址(8 字节)
#define DLT_LINUX_SLL_HEADER_LEN 16
// Ethernet frame 中可选项 8021Q 标识，占用 4 字节
#define VLAN_HEADER_LEN 4

/**
 * @brief Ethernet 报头
 * 
 */
struct sniff_ethernet {
    // 6 字节的 MAC 目的地址
    u_char ether_dhost[ETHER_ADDR_LEN];
    // 6 字节的 MAC 源地址
    u_char ether_shost[ETHER_ADDR_LEN];
    // 注意，这里还有 4 字节的可选 802.1q 标识
    // 已经在代码中做了处理
    // 2 字节的数据包类型/长度
    u_short ether_type;
};

/**
 * @brief IP 报头
 * 
 */
struct sniff_ip {
    // ip_v: 4 位的版本号
    // ip_hl: 4 位的首部长度
    // 注意是小端
    u_int ip_hl:4, ip_v:4;
    // 8 位的服务类型
    u_char ip_tos;
    // 16 位的总长度（字节数）
    u_short ip_len;
    // 16 位的标识
    u_short ip_id;
    // 3 位标志 + 13 位片偏移
    u_short ip_off;
    // 8 位的生存时间
    u_char ip_ttl;
    // 8 位协议
    u_char ip_p;
    // 16 位的首部校验和
    u_short ip_sum;
    // 32 位的源 IP 地址、32 位的目的 IP 地址
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
