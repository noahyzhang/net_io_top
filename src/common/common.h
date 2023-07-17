/**
 * @file common.h
 * @author your name (you@domain.com)
 * @brief 
 * @version 0.1
 * @date 2023-06-29
 * 
 * @copyright Copyright (c) 2023
 * 
 */

#ifndef SRC_COMMON_COMMON_H_
#define SRC_COMMON_COMMON_H_

#include <sys/types.h>
#include <stdint.h>
#include <string>

namespace net_io_top {

// PCAP 库中接口参数，用于接口：pcap_open_live
// 意为多长时间进行返回捕获的数据包
#define PCAP_POL_TO_MS 10
// PCAP 库中接口参数，用于接口：pcap_open_live
// 意为捕获的最大字节数，单位为字节
// 因为我们只关注不同层协议的报头，不关心内容
// 链路层(14字节)、网络层(20字节)、传输层(20字节)，设置 100 字节够了
// 同时，IP 报头最长 60字节，TCP 报头最长 60 字节
#define PCAP_SNAPLEN 100

/**
 * @brief IP 报文封装
 * 
 */
struct IpPacketWrap {
    // 这个指针指向 malloc 出来的内存块，不要忘记释放
    // 这个指针从 IP 报头开始
    u_char* ip_data;
    // 真实的 ip_data 的长度
    uint64_t real_ip_data_len;
    // 期望的 ip_data 的长度
    uint64_t expected_ip_data_len;
    struct timeval ts;
};

/**
 * @brief 传输层协议
 * 
 */
enum TransportLayerProtocol {
    TRANSPORT_LAYER_PROTOCOL_TCP = 0,
    TRANSPORT_LAYER_PROTOCOL_UDP
};

/**
 * @brief 连接的信息
 * 
 */
struct ConnectionInfo {
    TransportLayerProtocol protocol;
    std::string src_addr;
    std::string dst_addr;
    uint16_t src_port;
    uint16_t dst_port;
    uint64_t forward_packet_count;
    uint64_t forward_packet_bytes;
    uint64_t backward_packet_count;
    uint64_t backward_packet_bytes;
};

}  // namespace net_io_top

#endif  // SRC_COMMON_COMMON_H_
