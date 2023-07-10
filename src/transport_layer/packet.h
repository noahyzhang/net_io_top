/**
 * @file packet.h
 * @author your name (you@domain.com)
 * @brief 
 * @version 0.1
 * @date 2023-07-10
 * 
 * @copyright Copyright (c) 2023
 * 
 */

#ifndef SRC_TRANSPORT_LAYER_PACKET_H_
#define SRC_TRANSPORT_LAYER_PACKET_H_

#include <stdint.h>
#include "network_layer/ip_address.h"

namespace net_io_top {

class Packet {
public:

public:
    inline uint64_t get_total_len() const { return total_len_; }
    inline const IPAddress& get_src_addr() const { return ip_src_addr_; }
    inline const IPAddress& get_dst_addr() const { return ip_dst_addr_; }

private:
    // 报文总长度（从 IP 头算起）
    uint64_t total_len_{0};
    // IP 报文头部长度
    uint16_t ip_header_len_{0};
    // IP 源地址
    IPAddress* ip_src_addr_{nullptr};
    // IP 目的地址
    IPAddress* ip_dst_addr_{nullptr};
};

}  // namespace net_io_top

#endif  // SRC_TRANSPORT_LAYER_PACKET_H_
