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

namespace net_io_top {

// PCAP 库中接口参数，用于接口：pcap_open_live
// 意为多长时间进行返回捕获的数据包
#define PCAP_POL_TO_MS 10
// PCAP 库中接口参数，用于接口：pcap_open_live
// 意为捕获的最大字节数，单位为字节
// 因为我们只关注不同层协议的报头，不关心内容
// 链路层(14字节)、网络层(20字节)、传输层(20字节)，设置 100 字节够了
#define PCAP_SNAPLEN 100

/**
 * @brief IP 报头封装
 * 
 */
struct IpPacketWrap {
    // 这个指针指向 malloc 出来的内存块，不要忘记释放
    // 这个指针从 IP 报头开始
    u_char* ip_data;
    uint64_t ip_data_len;
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

}  // namespace net_io_top

#endif  // SRC_COMMON_COMMON_H_
