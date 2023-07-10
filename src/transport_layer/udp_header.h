/**
 * @file udp_header.h
 * @author your name (you@domain.com)
 * @brief 
 * @version 0.1
 * @date 2023-07-10
 * 
 * @copyright Copyright (c) 2023
 * 
 */

#ifndef SRC_TRANSPORT_LAYER_UDP_HEADER_H_
#define SRC_TRANSPORT_LAYER_UDP_HEADER_H_

#include <stdint.h>
#include <sys/types.h>
#include <netinet/in.h>
#include "common/headers.h"

namespace net_io_top {

/**
 * @brief UDP 头部
 * 
 */
class UdpHeader {
public:
    UdpHeader(const u_char* data, uint32_t data_len) {
        (void)data_len;
        struct sniff_udp* udp = (struct sniff_udp*)data;
        src_port_ = ntohs(udp->src_port);
        dst_port_ = ntohs(udp->dst_port);
        // 最小值为 8 字节，假定他是正确的
        packet_len_ = ntohs(udp->packet_len);
    }
    ~UdpHeader() = default;
    UdpHeader(const UdpHeader&) = delete;
    UdpHeader& operator=(const UdpHeader&) = delete;
    UdpHeader(UdpHeader&&) = delete;
    UdpHeader& operator=(UdpHeader&&) = delete;

public:
    inline uint16_t get_src_port() const { return src_port_; }
    inline uint16_t get_dst_port() const { return dst_port_; }
    inline uint16_t get_packet_len() const { return packet_len_; }

private:
    // 源端口号
    uint16_t src_port_{0};
    // 目的端口号
    uint16_t dst_port_{0};
    // 数据包长度
    uint16_t packet_len_{0};
    // 校验值不用管它了，当他是正确的
};

}  // namespace net_io_top

#endif  // SRC_TRANSPORT_LAYER_UDP_HEADER_H_
